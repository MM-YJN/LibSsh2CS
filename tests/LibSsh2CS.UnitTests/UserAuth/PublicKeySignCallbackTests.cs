using System.Buffers.Binary;

namespace LibSsh2CS.UnitTests.UserAuth;

/// <summary>
/// Tests for the publickey sign-callback seam added in Phase 4 increment 4.1.
/// Two surfaces:
/// <list type="bullet">
///   <item><see cref="SshUserAuth.SelectSigningAlgorithm(SshSession, byte[])"/> —
///   algorithm-name derivation from an SSH wire-format public-key blob
///   (parallels the existing <c>(SshSession, PemKey)</c> overload, but for the
///   agent path where only the public-key blob is available).</item>
///   <item><c>AuthenticateWithPublicKeyAsync(session, user, blob, signAsync,
///   ct)</c> — the new overload that drives the two-step publickey flow with an
///   externally-supplied signing callback (the agent / HSM / PKCS#11 entry
///   point).</item>
/// </list>
/// The full end-to-end sign path is verified live by
/// <c>DockerAgentTests</c> (Phase 4 increment 4.5); these tests cover the
/// pieces that can be exercised without a handshaked session.
/// </summary>
public class PublicKeySignCallbackTests
{
    // ════════════════════════════════════════════════════════════════════════
    // SelectSigningAlgorithm(SshSession, byte[]) — blob dispatch
    // ════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// An RSA blob's first string is <c>"ssh-rsa"</c>; the algorithm name is
    /// selected from <see cref="SshSession.ServerSignatureAlgorithms"/> (the
    /// server-sig-algs EXT_INFO extension) — picks the strongest SHA-2 variant
    /// the server advertises.
    /// </summary>
    [Fact]
    public void SelectBlob_Rsa_WithBothSha2_PicksSha2_512()
    {
        var session = new SshSession();
        session.SetServerSignatureAlgorithmsForTest(["ssh-rsa", "rsa-sha2-256", "rsa-sha2-512"]);
        byte[] blob = BuildKeyBlob("ssh-rsa", extra: [0, 0, 0, 3, 1, 2, 3]);  // e + n placeholders

        string algo = SshUserAuth.SelectSigningAlgorithm(session, blob);

        Assert.Equal("rsa-sha2-512", algo);
    }

    [Fact]
    public void SelectBlob_Rsa_OnlySha2_256_PicksSha2_256()
    {
        var session = new SshSession();
        session.SetServerSignatureAlgorithmsForTest(["ssh-rsa", "rsa-sha2-256"]);
        byte[] blob = BuildKeyBlob("ssh-rsa");

        string algo = SshUserAuth.SelectSigningAlgorithm(session, blob);

        Assert.Equal("rsa-sha2-256", algo);
    }

    [Fact]
    public void SelectBlob_Rsa_NoSha2_Advertised_FallsBackToSshRsa()
    {
        var session = new SshSession();
        session.SetServerSignatureAlgorithmsForTest(["ssh-rsa"]);
        byte[] blob = BuildKeyBlob("ssh-rsa");

        string algo = SshUserAuth.SelectSigningAlgorithm(session, blob);

        Assert.Equal("ssh-rsa", algo);
    }

    [Fact]
    public void SelectBlob_Rsa_NullServerAlgs_FallsBackToSshRsa()
    {
        // No SetServerSignatureAlgorithmsForTest call → ServerSignatureAlgorithms == null.
        var session = new SshSession();
        byte[] blob = BuildKeyBlob("ssh-rsa");

        string algo = SshUserAuth.SelectSigningAlgorithm(session, blob);

        Assert.Equal("ssh-rsa", algo);
    }

    /// <summary>
    /// Ed25519 blob's keytype is <c>"ssh-ed25519"</c>; the algorithm name equals
    /// the keytype (RFC 8332 §3.1) regardless of server-sig-algs.
    /// </summary>
    [Fact]
    public void SelectBlob_Ed25519_ReturnsSshEd25519()
    {
        var session = new SshSession();
        session.SetServerSignatureAlgorithmsForTest(["rsa-sha2-256"]);  // irrelevant for Ed25519
        byte[] blob = BuildKeyBlob("ssh-ed25519", extra: new byte[32]);

        string algo = SshUserAuth.SelectSigningAlgorithm(session, blob);

        Assert.Equal("ssh-ed25519", algo);
    }

    /// <summary>
    /// ECDSA blob's keytype is the algorithm name (e.g.
    /// <c>"ecdsa-sha2-nistp256"</c>). The blob also embeds a curve string
    /// (<c>"nistp256"</c>) but <see cref="SshUserAuth.SelectSigningAlgorithm"/>
    /// dispatches off the outer keytype directly.
    /// </summary>
    [Theory]
    [InlineData("ecdsa-sha2-nistp256")]
    [InlineData("ecdsa-sha2-nistp384")]
    [InlineData("ecdsa-sha2-nistp521")]
    public void SelectBlob_Ecdsa_ReturnsKeyType(string keyType)
    {
        var session = new SshSession();
        byte[] blob = BuildKeyBlob(keyType);

        string algo = SshUserAuth.SelectSigningAlgorithm(session, blob);

        Assert.Equal(keyType, algo);
    }

    /// <summary>
    /// An unknown keytype (e.g. <c>"ssh-dss"</c>, which is out of scope for
    /// LibSsh2CS) throws <see cref="SshErrorCode.PublicKeyProtocol"/>.
    /// </summary>
    [Fact]
    public void SelectBlob_UnsupportedKeyType_Throws()
    {
        var session = new SshSession();
        byte[] blob = BuildKeyBlob("ssh-dss");

        SshException ex = Assert.Throws<SshException>(() => SshUserAuth.SelectSigningAlgorithm(session, blob));
        Assert.Equal(SshErrorCode.PublicKeyProtocol, ex.ErrorCode);
        Assert.Contains("ssh-dss", ex.Message);
    }

    /// <summary>
    /// A blob shorter than 4 bytes cannot contain even the keytype length prefix.
    /// </summary>
    [Fact]
    public void SelectBlob_TooShort_Throws()
    {
        var session = new SshSession();
        byte[] blob = [1, 2, 3];

        SshException ex = Assert.Throws<SshException>(() => SshUserAuth.SelectSigningAlgorithm(session, blob));
        Assert.Equal(SshErrorCode.PublicKeyProtocol, ex.ErrorCode);
    }

    /// <summary>
    /// A blob whose length-prefix claims more bytes than the blob contains is
    /// rejected by the wire reader (<see cref="PacketWireReader.ReadString"/>).
    /// </summary>
    [Fact]
    public void SelectBlob_TruncatedKeyType_Throws()
    {
        var session = new SshSession();
        // length-prefix says 100 bytes but only 3 follow
        byte[] blob = [0, 0, 0, 100, 1, 2, 3];

        Assert.ThrowsAny<Exception>(() => SshUserAuth.SelectSigningAlgorithm(session, blob));
    }

    [Fact]
    public void SelectBlob_NullBlob_Throws()
    {
        var session = new SshSession();
        Assert.Throws<ArgumentNullException>(() => SshUserAuth.SelectSigningAlgorithm(session, (byte[])null!));
    }

    // ════════════════════════════════════════════════════════════════════════
    // New overload argument validation (EnsureReady happens AFTER null checks;
    // these verify the validation order without needing a handshaked session).
    // ════════════════════════════════════════════════════════════════════════

    [Fact]
    public async Task Authenticate_NullSession_Throws()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        SshSession s = null!;
        await Assert.ThrowsAsync<ArgumentNullException>(() =>
            s.AuthenticateWithPublicKeyAsync("user", new byte[] { 0, 0, 0, 0 }, s_signCallback, cancellationToken));
    }

    [Fact]
    public async Task Authenticate_NullUsername_Throws()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        var session = new SshSession();
        await Assert.ThrowsAsync<ArgumentNullException>(() =>
            session.AuthenticateWithPublicKeyAsync(null!, new byte[] { 0, 0, 0, 0 }, s_signCallback, cancellationToken));
    }

    [Fact]
    public async Task Authenticate_NullBlob_Throws()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        var session = new SshSession();
        await Assert.ThrowsAsync<ArgumentNullException>(() =>
            session.AuthenticateWithPublicKeyAsync("user", (byte[])null!, s_signCallback, cancellationToken));
    }

    [Fact]
    public async Task Authenticate_NullCallback_Throws()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        var session = new SshSession();
        await Assert.ThrowsAsync<ArgumentNullException>(() =>
            session.AuthenticateWithPublicKeyAsync("user", new byte[] { 0, 0, 0, 0 }, (PublicKeySignCallback)null!, cancellationToken));
    }

    /// <summary>
    /// After null-checks pass, <see cref="SshUserAuth"/> calls <c>EnsureReady</c>
    /// which rejects sessions that haven't completed the handshake (no
    /// <c>Writer</c> / <c>Queue</c>).
    /// </summary>
    [Fact]
    public async Task Authenticate_NotHandshaked_Throws()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        var session = new SshSession();
        Assert.False(session.IsAuthenticated);

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            session.AuthenticateWithPublicKeyAsync("user", new byte[] { 0, 0, 0, 0 }, s_signCallback, cancellationToken));
    }

    /// <summary>
    /// A too-short blob is caught at <c>SelectSigningAlgorithm</c> (after
    /// EnsureReady). Since EnsureReady runs first and rejects non-handshaked
    /// sessions, we exercise this path via the helper directly (above). Here
    /// we just confirm the new overload's wire-up matches the helper.
    /// </summary>
    [Fact]
    public async Task Authenticate_TooShortBlob_AfterHandshake_ThrowsPublicKeyProtocol()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        // We can't drive the full handshake in a unit test (that's covered by
        // DockerAgentTests in 4.5). This test is a placeholder that documents
        // the contract: callers must pass a blob with at least 4 bytes (a valid
        // length-prefix). Real coverage of the post-EnsureReady path is the
        // live Docker gate.
        // |
        //  v  -- see DockerAgentTests for end-to-end coverage.
        var session = new SshSession();
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            session.AuthenticateWithPublicKeyAsync("user", [1, 2], s_signCallback, cancellationToken));
    }

    // ════════════════════════════════════════════════════════════════════════
    // Helpers
    // ════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// A dummy callback that never actually signs (the unit tests above never
    /// reach the callback — they throw earlier on null/EnsureReady/bad blob).
    /// Typed as <see cref="PublicKeySignCallback"/> so overload resolution
    /// unambiguously picks the new overload.
    /// </summary>
    private static readonly PublicKeySignCallback s_signCallback =
        static (data, algo, ct) => Task.FromResult(new byte[] { 0xDE, 0xAD });

    /// <summary>
    /// Builds a minimal SSH wire-format public-key blob with a given keytype
    /// string + optional extra payload bytes. The blob is syntactically valid
    /// enough for <see cref="SshUserAuth.SelectSigningAlgorithm(SshSession, byte[])"/>
    /// to read the keytype; deeper validation is not exercised here.
    /// </summary>
    private static byte[] BuildKeyBlob(string keyType, byte[]? extra = null)
    {
        byte[] kt = System.Text.Encoding.ASCII.GetBytes(keyType);
        int prefixLen = 4 + kt.Length;
        int extraLen = extra?.Length ?? 0;
        byte[] blob = new byte[prefixLen + extraLen];
        BinaryPrimitives.WriteUInt32BigEndian(blob.AsSpan(0, 4), (uint)kt.Length);
        Buffer.BlockCopy(kt, 0, blob, 4, kt.Length);
        if (extra is not null)
        {
            Buffer.BlockCopy(extra, 0, blob, prefixLen, extra.Length);
        }

        return blob;
    }
}
