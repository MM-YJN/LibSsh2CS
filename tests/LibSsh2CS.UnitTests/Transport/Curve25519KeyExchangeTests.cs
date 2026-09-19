using LibSsh2CS.Transport;

namespace LibSsh2CS.UnitTests.Transport;

/// <summary>
/// Tests for <see cref="Curve25519KeyExchange"/>: ephemeral keypair format,
/// two-party shared-secret symmetry, and the RFC 7748 §6.1 fixed DH vectors
/// (run through the public surface via the internal test-only ctor that
/// imports an explicit private key).
/// </summary>
public class Curve25519KeyExchangeTests
{
    [Fact]
    public void PublicKey_Is32Bytes()
    {
        using var k = new Curve25519KeyExchange();
        Assert.Equal(32, k.PublicKey.Length);
    }

    [Fact]
    public void TwoParty_SharedSecretIsSymmetric()
    {
        using var alice = new Curve25519KeyExchange();
        using var bob = new Curve25519KeyExchange();

        byte[] kAlice = alice.ComputeSharedSecret(bob.PublicKey);
        byte[] kBob = bob.ComputeSharedSecret(alice.PublicKey);

        Assert.Equal(kAlice, kBob);
        Assert.Equal(32, kAlice.Length);
    }

    [Fact]
    public void ComputeSharedSecret_WrongLength_ThrowsKexFailure()
    {
        using var k = new Curve25519KeyExchange();
        byte[] bad = new byte[31];

        SshException ex = Assert.Throws<SshException>(() => k.ComputeSharedSecret(bad));
        Assert.Equal(SshErrorCode.KexFailure, ex.ErrorCode);
    }

    [Fact]
    public void ComputeSharedSecret_LowOrderPublicKey_ThrowsKexFailure()
    {
        using var k = new Curve25519KeyExchange();
        byte[] lowOrder = new byte[32];   // u = 0 is rejected by the BCL backend

        SshException ex = Assert.Throws<SshException>(() => k.ComputeSharedSecret(lowOrder));
        Assert.Equal(SshErrorCode.KexFailure, ex.ErrorCode);
    }

    /// <summary>
    /// RFC 7748 §6.1 Diffie-Hellman: each party's X25519(priv, basepoint 9)
    /// produces their public key, and X25519(priv, peer_pub) produces the shared
    /// secret. Exercises the full ECDH flow used by curve25519 KEX, against the
    /// canonical interop vectors.
    /// </summary>
    [Fact]
    public void DiffieHellman_Rfc7748_6_1_BothParties_ConvergeOnSharedSecret()
    {
        byte[] alicePriv = Convert.FromHexString("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        byte[] bobPriv = Convert.FromHexString("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
        byte[] expectedAlicePub = Convert.FromHexString("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
        byte[] expectedBobPub = Convert.FromHexString("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
        byte[] expectedShared = Convert.FromHexString("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

        using var alice = new Curve25519KeyExchange(alicePriv);
        using var bob = new Curve25519KeyExchange(bobPriv);
        Assert.Equal(expectedAlicePub, alice.PublicKey);
        Assert.Equal(expectedBobPub, bob.PublicKey);

        byte[] sharedFromAlice = alice.ComputeSharedSecret(bob.PublicKey);
        byte[] sharedFromBob = bob.ComputeSharedSecret(alice.PublicKey);
        Assert.Equal(expectedShared, sharedFromAlice);
        Assert.Equal(expectedShared, sharedFromBob);
    }

    /// <summary>
    /// RFC 7748 §6.1 iteration test, 1 iteration: starting from
    /// 090000...0000, one application of X25519(k=seed, u=seed) yields the
    /// documented value. (The 1,000-iteration and 1,000,000-iteration values
    /// are the same test at larger scale; one iteration is enough to validate
    /// the ladder end-to-end and is the value CI runs.)
    /// </summary>
    [Fact]
    public void Iteration_Rfc7748_6_1_OneIteration_Matches()
    {
        byte[] seed = new byte[32];
        seed[0] = 0x09;
        byte[] expectedAfterOne = Convert.FromHexString("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079");

        using var k = new Curve25519KeyExchange(seed);
        byte[] actual = k.ComputeSharedSecret(seed);
        Assert.Equal(expectedAfterOne, actual);
    }

    /// <summary>
    /// RFC 7748 §6.1 iteration test, 1,000 iterations. Slower but exercises the
    /// ladder under feedback (output fed back as next scalar and u-coordinate),
    /// which catches subtle reduction/encoding bugs that single-shot vectors miss.
    /// </summary>
    [Fact]
    public void Iteration_Rfc7748_6_1_ThousandIterations_Matches()
    {
        byte[] seed = new byte[32];
        seed[0] = 0x09;
        byte[] expected = Convert.FromHexString("684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51");

        // RFC 7748 §6.1: "For each iteration, set k to be the result of calling
        // the function and u to be the OLD value of k." So u lags one step
        // behind k — it is NOT set to the current k before computing.
        byte[] k = seed;
        byte[] u = seed;
        for (int i = 0; i < 1000; i++)
        {
            using var kp = new Curve25519KeyExchange(k);
            byte[] newK = kp.ComputeSharedSecret(u);
            u = k;
            k = newK;
        }

        Assert.Equal(expected, k);
    }
}
