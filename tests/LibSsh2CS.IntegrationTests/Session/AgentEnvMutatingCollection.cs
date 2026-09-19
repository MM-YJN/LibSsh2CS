using Xunit;

namespace LibSsh2CS.IntegrationTests.Session;

/// <summary>
/// Marker collection for tests that mutate process-global state (currently
/// <c>SSH_AUTH_SOCK</c>). xUnit v3 serializes test classes that share a
/// collection, so <see cref="DockerAgentTests.Agent_ParameterlessCtor_ResolvesAuthSockEnvVar"/>
/// cannot race another agent test that might read the env var concurrently.
/// </summary>
/// <remarks>
/// The collection has no <c>ICollectionFixture</c>; it serves only as a
/// serialization boundary. Tests in the collection still own their own
/// per-test <c>HostSshAgent</c> instance — no shared state is mutated beyond
/// the env var, and the env var is restored in <c>finally</c>.
/// </remarks>
[CollectionDefinition("agent-env-mutating")]
public sealed class AgentEnvMutatingCollection
{
}
