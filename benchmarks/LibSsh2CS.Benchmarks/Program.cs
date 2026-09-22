using BenchmarkDotNet.Running;

using LibSsh2CS.Benchmarks;

BenchmarkSwitcher.FromAssembly(typeof(BenchmarkConfig).Assembly).Run(args, new BenchmarkConfig());
