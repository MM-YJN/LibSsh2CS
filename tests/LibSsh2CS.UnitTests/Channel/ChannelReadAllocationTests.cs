namespace LibSsh2CS.UnitTests.Channel;

public class ChannelReadAllocationTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task BufferedPartialReads_CompleteSynchronously(bool stderr)
    {
        const int reads = 64;
        const int chunkSize = 64; // Above the cached Task<int> result range.
        using var h = new ChannelTestHarness();
        SshChannel channel = h.CreateChannel();
        byte[] data = new byte[(reads * 2 + 1) * chunkSize];
        Array.Fill(data, (byte)0x5a);
        byte[] payload = stderr
            ? ChannelTestHarness.BuildChannelExtendedDataPayload(channel.LocalId, 1, data)
            : ChannelTestHarness.BuildChannelDataPayload(channel.LocalId, data);
        await h.FeedInboundAsync(ChannelTestHarness.BuildCleartextPacket(payload[0], payload));
        await h.Router.PumpOneBatchForTestAsync(TestContext.Current.CancellationToken);
        byte[] output = new byte[chunkSize];

        // Warm both the read path and the measurement helper. Data is already
        // routed, and the default window is large enough to avoid adjustments.
        // Leave one chunk buffered so pool-return initialization is not measured.
        Assert.Equal(reads * chunkSize, ReadBuffered(channel, output, stderr, reads));
#if !DEBUG
        // Debug builds allocate async state-machine objects even on synchronous completion.
        long before = GC.GetAllocatedBytesForCurrentThread();
#endif
        int total = ReadBuffered(channel, output, stderr, reads);
#if !DEBUG
        long allocated = GC.GetAllocatedBytesForCurrentThread() - before;
        Assert.Equal(0L, allocated);
#endif

        Assert.Equal(reads * chunkSize, total);
        Assert.All(output, value => Assert.Equal((byte)0x5a, value));
    }

    private static int ReadBuffered(SshChannel channel, byte[] output, bool stderr, int reads)
    {
        int total = 0;
        for (int i = 0; i < reads; i++)
        {
            ValueTask<int> read = stderr
                ? channel.ReadStderrAsync(output)
                : channel.ReadAsync(output);
            if (!read.IsCompletedSuccessfully)
            {
                throw new InvalidOperationException("Expected a synchronous buffered read.");
            }
            total += read.GetAwaiter().GetResult();
        }
        return total;
    }
}
