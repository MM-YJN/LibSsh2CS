using LibSsh2CS.Transport;

using Microsoft.Extensions.Time.Testing;

namespace LibSsh2CS.UnitTests.Session;

/// <summary>
/// Set-time preference filtering on <see cref="SshSession"/>'s indexer —
/// parity with <c>libssh2_session_method_pref</c>'s strip loop
/// (kex.c:4283-4315).
/// </summary>
public class PrefFilterTests
{
    [Fact]
    public void Set_Kex_StripsUnknownNames_KeepsKnown()
    {
        var session = new SshSession(new FakeTimeProvider());

        session[SshMethodType.Kex] = "curve25519-sha256,nonexistent-kex,diffie-hellman-group14-sha256";

        Assert.Equal("curve25519-sha256,diffie-hellman-group14-sha256", session[SshMethodType.Kex]);
    }

    [Fact]
    public void Set_HostKey_StripsDeferredNames()
    {
        var session = new SshSession(new FakeTimeProvider());

        // ssh-dss and cert variants are out of scope — stripped like the C
        // strips names its method table lacks.
        session[SshMethodType.HostKey] = "ssh-ed25519,ssh-dss,ssh-rsa-cert-v01@openssh.com";

        Assert.Equal("ssh-ed25519", session[SshMethodType.HostKey]);
    }

    [Fact]
    public void Set_Crypt_AllStripped_ThrowsMethodNotSupported()
    {
        var session = new SshSession(new FakeTimeProvider());

        SshException ex = Assert.Throws<SshException>(() =>
            session[SshMethodType.CryptCs] = "blowfish-cbc,arcfour");

        Assert.Equal(SshErrorCode.MethodNotSupported, ex.ErrorCode);
    }

    [Fact]
    public void Set_Kex_AllStripped_DoesNotThrow()
    {
        // The C prepends ext-info-c/kex-strict-c-v00@openssh.com, so an
        // all-stripped KEX list stays non-empty (kex.c:4199-4216, 4310-4315).
        var session = new SshSession(new FakeTimeProvider());

        session[SshMethodType.Kex] = "nonexistent-kex";

        Assert.Equal(string.Empty, session[SshMethodType.Kex]);
    }

    [Fact]
    public void Set_SignAlgo_StoredVerbatim()
    {
        // SIGN_ALGO has no method table (mlist NULL, kex.c:4263-4266) — any
        // value is stored verbatim.
        var session = new SshSession(new FakeTimeProvider());

        session[SshMethodType.SignAlgo] = "ssh-rsa,rsa-sha2-256,rsa-sha2-512";

        Assert.Equal("ssh-rsa,rsa-sha2-256,rsa-sha2-512", session[SshMethodType.SignAlgo]);
    }

    [Fact]
    public void Set_EmptyString_RemainsUnsetSentinel()
    {
        var session = new SshSession(new FakeTimeProvider());

        session[SshMethodType.MacCs] = string.Empty;

        Assert.Equal(string.Empty, session[SshMethodType.MacCs]);
    }
}
