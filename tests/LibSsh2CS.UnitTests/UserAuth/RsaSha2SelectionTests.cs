namespace LibSsh2CS.UnitTests.UserAuth;

/// <summary>
/// RSA-SHA2 algorithm selection tests — verifies the
/// <c>UserAuth.SelectSigningAlgorithm</c> dispatch picks the strongest
/// mutually-supported RSA-SHA2 variant from <c>server-sig-algs</c>, falling
/// back to <c>ssh-rsa</c> (SHA-1) when the server advertises no SHA-2 variant.
/// Parity with <c>_libssh2_key_sign_algorithm</c> (<c>userauth.c:1351</c>).
/// </summary>
/// <remarks>
/// The selection is the parity-critical decision for RSA userauth: OpenSSH 8.2+
/// disables <c>ssh-rsa</c> (SHA-1) by default, so an RSA key MUST sign with
/// <c>rsa-sha2-256</c> or <c>rsa-sha2-512</c> when the server advertises them.
/// </remarks>
public class RsaSha2SelectionTests
{
    /// <summary>
    /// When the server advertises both rsa-sha2-256 and rsa-sha2-512, the client
    /// picks the strongest (rsa-sha2-512).
    /// </summary>
    [Fact]
    public void Select_BothSha2Variants_PicksSha2_512()
    {
        var session = new SshSession();
        session.SetServerSignatureAlgorithmsForTest(["ssh-rsa", "rsa-sha2-256", "rsa-sha2-512"]);
        RsaPemKey rsa = LoadRsaKey();

        string algo = SshUserAuth.SelectSigningAlgorithm(session, rsa);
        Assert.Equal("rsa-sha2-512", algo);
    }

    /// <summary>
    /// When the server advertises only rsa-sha2-256, the client picks it.
    /// </summary>
    [Fact]
    public void Select_OnlySha2_256_PicksSha2_256()
    {
        var session = new SshSession();
        session.SetServerSignatureAlgorithmsForTest(["ssh-rsa", "rsa-sha2-256"]);
        RsaPemKey rsa = LoadRsaKey();

        string algo = SshUserAuth.SelectSigningAlgorithm(session, rsa);
        Assert.Equal("rsa-sha2-256", algo);
    }

    /// <summary>
    /// When the server advertises no SHA-2 variant (only ssh-rsa), the client
    /// falls back to ssh-rsa (SHA-1). OpenSSH 8.2+ will reject this; the caller's
    /// retry loop (Phase N) handles the failure.
    /// </summary>
    [Fact]
    public void Select_OnlySshRsa_FallsBackToSshRsa()
    {
        var session = new SshSession();
        session.SetServerSignatureAlgorithmsForTest(["ssh-rsa"]);
        RsaPemKey rsa = LoadRsaKey();

        string algo = SshUserAuth.SelectSigningAlgorithm(session, rsa);
        Assert.Equal("ssh-rsa", algo);
    }

    /// <summary>
    /// When the server advertises an empty server-sig-algs list, the client
    /// falls back to ssh-rsa (SHA-1).
    /// </summary>
    [Fact]
    public void Select_EmptyServerAlgs_FallsBackToSshRsa()
    {
        var session = new SshSession();
        session.SetServerSignatureAlgorithmsForTest([]);
        RsaPemKey rsa = LoadRsaKey();

        string algo = SshUserAuth.SelectSigningAlgorithm(session, rsa);
        Assert.Equal("ssh-rsa", algo);
    }

    /// <summary>
    /// When no EXT_INFO was received (ServerSignatureAlgorithms is null), the
    /// client falls back to ssh-rsa (SHA-1).
    /// </summary>
    [Fact]
    public void Select_NullServerAlgs_FallsBackToSshRsa()
    {
        var session = new SshSession();
        // No SetServerSignatureAlgorithmsForTest call → null
        RsaPemKey rsa = LoadRsaKey();

        string algo = SshUserAuth.SelectSigningAlgorithm(session, rsa);
        Assert.Equal("ssh-rsa", algo);
    }

    /// <summary>
    /// When the server lists only rsa-sha2-512 (not 256), the client picks 512.
    /// </summary>
    [Fact]
    public void Select_OnlySha2_512_PicksSha2_512()
    {
        var session = new SshSession();
        session.SetServerSignatureAlgorithmsForTest(["rsa-sha2-512"]);
        RsaPemKey rsa = LoadRsaKey();

        string algo = SshUserAuth.SelectSigningAlgorithm(session, rsa);
        Assert.Equal("rsa-sha2-512", algo);
    }

    /// <summary>
    /// When the server lists rsa-sha2-256 BEFORE rsa-sha2-512, the client still
    /// prefers 512 (strongest wins, regardless of server order — parity with
    /// the C pref-match loop).
    /// </summary>
    [Fact]
    public void Select_ServerLists256Before512_StillPicks512()
    {
        var session = new SshSession();
        session.SetServerSignatureAlgorithmsForTest(["rsa-sha2-256", "rsa-sha2-512"]);
        RsaPemKey rsa = LoadRsaKey();

        string algo = SshUserAuth.SelectSigningAlgorithm(session, rsa);
        Assert.Equal("rsa-sha2-512", algo);
    }

    /// <summary>
    /// An Ed25519 key always selects "ssh-ed25519" regardless of
    /// server-sig-algs (the algorithm is fixed by the key type).
    /// </summary>
    [Fact]
    public void Select_Ed25519Key_AlwaysPicksSshEd25519()
    {
        var session = new SshSession();
        session.SetServerSignatureAlgorithmsForTest(["ssh-rsa", "rsa-sha2-256"]);
        SshEd25519PemKey ed = LoadEd25519Key();

        string algo = SshUserAuth.SelectSigningAlgorithm(session, ed);
        Assert.Equal("ssh-ed25519", algo);
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private static RsaPemKey LoadRsaKey()
    {
        byte[] keyBytes = FixtureLoader.LoadBytes("rsa_plain_key");
        OpenSshKey openSshKey = SshPemParser.ParseOpenSshPrivateKey(keyBytes, passphrase: null);
        return (RsaPemKey)SshPemKey.Parse(openSshKey);
    }

    private static SshEd25519PemKey LoadEd25519Key()
    {
        byte[] keyBytes = FixtureLoader.LoadBytes("ed25519_plain_key");
        OpenSshKey openSshKey = SshPemParser.ParseOpenSshPrivateKey(keyBytes, passphrase: null);
        return (SshEd25519PemKey)SshPemKey.Parse(openSshKey);
    }
}
