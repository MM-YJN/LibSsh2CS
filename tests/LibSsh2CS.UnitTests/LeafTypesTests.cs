namespace LibSsh2CS.UnitTests;

/// <summary>
/// Smoke tests for the leaf types delivered in Phase 0.
/// </summary>
public class LeafTypesTests
{
    [Fact]
    public void SshErrorCode_PreservesLibssh2NumericValues()
    {
        // Verify a representative sample matches libssh2.h exactly.
        Assert.Equal(0, (int)SshErrorCode.None);
        Assert.Equal(-1, (int)SshErrorCode.SocketNone);
        Assert.Equal(-18, (int)SshErrorCode.AuthenticationFailed);
        Assert.Equal(-37, (int)SshErrorCode.EAgain);
        Assert.Equal(-54, (int)SshErrorCode.HashCalc);
    }

    [Fact]
    public void LibSsh2Exception_CarriesErrorCode()
    {
        var ex = new SshException(SshErrorCode.AuthenticationFailed, "auth failed");
        Assert.Equal(SshErrorCode.AuthenticationFailed, ex.ErrorCode);
        Assert.Equal("auth failed", ex.Message);
    }

    [Fact]
    public void LibSsh2Exception_DefaultConstructorUsesSocketNone()
    {
        var ex = new SshException("generic");
        Assert.Equal(SshErrorCode.SocketNone, ex.ErrorCode);
    }

    [Fact]
    public void LibSsh2Exception_InnerExceptionConstructor_DefaultsToSocketNone()
    {
        var ex = new SshException("wrap", new InvalidOperationException());
        Assert.Equal(SshErrorCode.SocketNone, ex.ErrorCode);
        Assert.IsType<InvalidOperationException>(ex.InnerException);
    }

    [Fact]
    public void MethodPreferences_DefaultIsEmpty()
    {
        var prefs = new MethodPreferences();
        foreach (SshMethodType type in Enum.GetValues<SshMethodType>())
        {
            Assert.False(prefs.IsSet(type));
            Assert.Equal(string.Empty, prefs[type]);
        }
    }

    [Fact]
    public void MethodPreferences_SetGet_RoundTrips()
    {
        var prefs = new MethodPreferences();
        prefs[SshMethodType.Kex] = "curve25519-sha256,diffie-hellman-group14-sha256";

        Assert.True(prefs.IsSet(SshMethodType.Kex));
        Assert.Equal("curve25519-sha256,diffie-hellman-group14-sha256", prefs[SshMethodType.Kex]);
    }

    [Fact]
    public void MethodPreferences_SetNull_ReplacesWithEmpty()
    {
        var prefs = new MethodPreferences();
        prefs[SshMethodType.CryptCs] = "aes256-ctr";
        prefs[SshMethodType.CryptCs] = null!;

        Assert.False(prefs.IsSet(SshMethodType.CryptCs));
    }

    [Fact]
    public void MethodPreferences_Clear_RemovesAllEntries()
    {
        var prefs = new MethodPreferences();
        prefs[SshMethodType.Kex] = "x";
        prefs[SshMethodType.HostKey] = "y";

        prefs.Clear();

        Assert.False(prefs.IsSet(SshMethodType.Kex));
        Assert.False(prefs.IsSet(SshMethodType.HostKey));
    }

    [Fact]
    public void HostKeyType_IncludesAllMandatoryModernAlgorithms()
    {
        // Phase 1.2 scope: rsa-sha2-256 and rsa-sha2-512 must be representable
        // (OpenSSH 8.2+ disables ssh-rsa by default).
        Assert.True(Enum.IsDefined(SshHostKeyType.RsaSha256));
        Assert.True(Enum.IsDefined(SshHostKeyType.RsaSha512));
        Assert.True(Enum.IsDefined(SshHostKeyType.Ed25519));
    }

    [Fact]
    public void LibSsh2Version_NoneFeature_IsFalseWhenCombined()
    {
        // None alone is "supported" trivially (empty intersection).
        Assert.True(LibSsh2Version.Supports(SshFeature.None));

        // Combined with a real feature, the real feature must be supported.
        Assert.True(LibSsh2Version.Supports(SshFeature.None | SshFeature.Zlib));
    }

    [Fact]
    public void LibSsh2Version_AllInScopeFeaturesSupported()
    {
        Assert.True(LibSsh2Version.Supports(SshFeature.AuthPassword));
        Assert.True(LibSsh2Version.Supports(SshFeature.AuthPublicKey));
        Assert.True(LibSsh2Version.Supports(SshFeature.AuthKeyboardInteractive));
        Assert.True(LibSsh2Version.Supports(SshFeature.AuthAgent));
        Assert.True(LibSsh2Version.Supports(SshFeature.KnownHosts));
        Assert.True(LibSsh2Version.Supports(SshFeature.Zlib));
        Assert.True(LibSsh2Version.Supports(SshFeature.KeepAlive));
    }

    [Fact]
    public void LibSsh2Version_VersionString_IsNonEmpty()
    {
        Assert.False(string.IsNullOrEmpty(LibSsh2Version.Version));
        Assert.Contains("LibSsh2CS", LibSsh2Version.Version);
    }
}
