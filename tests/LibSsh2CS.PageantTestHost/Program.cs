using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;

using Windows.Win32;
using Windows.Win32.Foundation;
using Windows.Win32.System.DataExchange;
using Windows.Win32.System.Memory;
using Windows.Win32.UI.WindowsAndMessaging;

namespace LibSsh2CS.PageantTestHost;

/// <summary>
/// A standalone fake Pageant used by the Windows IPC integration tests. It
/// registers a window (a caller-supplied class name, normally a GUID, so it can
/// never collide with the real Pageant window) and answers
/// <c>WM_COPYDATA</c> requests through the same shared-mapping mechanism
/// Pageant uses.
/// </summary>
/// <remarks>
/// <para>
/// This host deliberately does <b>not</b> reference LibSsh2CS: the agent
/// protocol framing here is written independently, so a bug in the production
/// encoder cannot make a broken round trip look correct. That also keeps the
/// fixture honest about being a peer process rather than a re-hosted copy of
/// the code under test.
/// </para>
/// <para>
/// It runs in its own process because the transport's real behavior depends on
/// cross-process window-message marshalling: a window on the calling thread's
/// own queue is called directly and never crosses a process boundary.
/// </para>
/// <para>
/// On start it prints a single <c>READY</c> line to standard output — the
/// window class it registered plus the exact key and signature blobs it will
/// return, base64 encoded — so the test can assert byte equality without
/// duplicating the encoder. The parent kills the process when the test is done.
/// </para>
/// <para>
/// The <c>hang</c> behavior additionally prints <c>HANGING</c> when it enters
/// its delay and <c>SERVED</c> after it has read and answered a request, so a
/// test can observe that a receiver which outlives the client still uses the
/// shared mapping successfully.
/// </para>
/// <para>
/// The Win32 entry points and types come from CsWin32, generated from the Win32
/// metadata as source-generated <c>LibraryImport</c> methods, so the window
/// class holds a real function pointer and no call depends on the runtime
/// marshaler.
/// </para>
/// </remarks>
[SupportedOSPlatform("windows")]
[SuppressMessage("Platform Compatibility", "CA1416:Validate platform compatibility", Justification = "The generated entry points name the Windows version each one first appeared in — 5.0 for the window and message calls, 5.1.2600 for the module handle and the mapping calls. This fixture only ever runs on Windows, and it is built and launched by the IPC tests rather than referenced as a library, so those distinctions carry no information here.")]
internal static class Program
{
    /// <summary>
    /// <c>FILE_MAP_WRITE</c> grants read and write access to a section view,
    /// which is exactly what serving one request needs — and it is what Pageant
    /// itself passes to <c>OpenFileMapping</c>/<c>MapViewOfFile</c>.
    /// </summary>
    private const FILE_MAP FileMapWrite = FILE_MAP.FILE_MAP_WRITE;

    /// <summary>
    /// Pageant's marker for <c>COPYDATASTRUCT.dwData</c>
    /// (<c>PAGEANT_COPYDATA_ID</c> in libssh2's <c>agent.c</c>), spelled out
    /// here like the rest of the protocol constants.
    /// </summary>
    private const nuint PageantCopyDataId = 0x804e50ba;

    // Pageant protocol constants (PROTOCOL.agent), spelled out here so this
    // host shares no code with the library it validates.
    private const byte MsgRequestIdentities = 11;
    private const byte MsgIdentitiesAnswer = 12;
    private const byte MsgSignRequest = 13;
    private const byte MsgSignResponse = 14;
    private const byte MsgFailure = 5;

    private const int MaxPayloadLength = 8188;

    /// <summary>
    /// Size of the mapping the client creates for one request: the payload
    /// limit plus the 4-byte big-endian length prefix.
    /// </summary>
    private const int MappingLength = MaxPayloadLength + sizeof(uint);

    private static readonly byte[] s_identityBlob = BuildIdentityBlob();
    private static readonly byte[] s_signatureBlob = BuildSignatureBlob();

    private static string s_behavior = "normal";
    private static int s_hangMilliseconds = 15_000;

    private static unsafe int Main(string[] args)
    {
        if (!TryParseArguments(args, out string? className, out string? windowTitle, out string? error))
        {
            Console.Error.WriteLine(error);
            return 2;
        }

        HMODULE instance = PInvoke.GetModuleHandle(default(PCWSTR));

        // Registration copies the class name, so the pinned copy only has to
        // live until RegisterClassEx returns; the window below is then created
        // from the registered class.
        fixed (char* classNamePointer = className)
        {
            WNDCLASSEXW windowClass = new()
            {
                cbSize = (uint)sizeof(WNDCLASSEXW),
                lpfnWndProc = &StaticWindowProc,
                hInstance = instance,
                lpszClassName = classNamePointer,
            };

            if (PInvoke.RegisterClassEx(in windowClass) == 0)
            {
                Console.Error.WriteLine($"RegisterClassEx failed ({Marshal.GetLastPInvokeError()}).");
                return 3;
            }
        }

        // Created hidden: FindWindow locates it regardless of visibility,
        // and it never appears on the developer's desktop.
        HWND window;
        fixed (char* classNamePointer = className)
        fixed (char* windowTitlePointer = windowTitle)
        {
            window = PInvoke.CreateWindowEx(
                default,
                classNamePointer,
                windowTitlePointer,
                default,
                0,
                0,
                0,
                0,
                default,
                default,
                instance,
                null);
        }

        if (window.IsNull)
        {
            Console.Error.WriteLine($"CreateWindow failed ({Marshal.GetLastPInvokeError()}).");
            return 4;
        }

        Console.WriteLine(string.Join(
            ' ',
            "READY",
            className,
            Convert.ToBase64String(s_identityBlob),
            Convert.ToBase64String(s_signatureBlob)));
        Console.Out.Flush();

        return RunMessageLoop();
    }

    private static bool TryParseArguments(
        string[] args, out string className, out string windowTitle, out string? error)
    {
        className = string.Empty;
        windowTitle = string.Empty;
        error = null;

        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--class" when i + 1 < args.Length:
                    className = args[++i];
                    break;
                case "--title" when i + 1 < args.Length:
                    windowTitle = args[++i];
                    break;
                case "--behavior" when i + 1 < args.Length:
                    s_behavior = args[++i];
                    break;
                case "--hang-ms" when i + 1 < args.Length:
                    s_hangMilliseconds = int.Parse(args[++i], System.Globalization.CultureInfo.InvariantCulture);
                    break;
                default:
                    error = $"unrecognized or incomplete argument: {args[i]}";
                    return false;
            }
        }

        if (className.Length == 0)
        {
            error = "--class is required";
            return false;
        }

        if (windowTitle.Length == 0)
        {
            windowTitle = className;
        }

        switch (s_behavior)
        {
            case "normal":
            case "reject":
            case "hang":
            case "overlong":
            case "zero":
                return true;
            default:
                error = $"unknown behavior: {s_behavior}";
                return false;
        }
    }

    private static int RunMessageLoop()
    {
        while (true)
        {
            int result = PInvoke.GetMessage(out MSG message, default, 0, 0);
            if (result == 0)
            {
                return 0;      // WM_QUIT
            }

            if (result == -1)
            {
                return 5;      // GetMessage error
            }

            _ = PInvoke.TranslateMessage(in message);
            _ = PInvoke.DispatchMessage(in message);
        }
    }

    /// <summary>
    /// The window procedure. It is marked as an unmanaged callback using the
    /// <c>Stdcall</c> convention of <see cref="WNDCLASSEXW.lpfnWndProc"/>, so
    /// the operating system calls it directly — no managed thunk is generated
    /// and no delegate has to be kept alive for the window's lifetime.
    /// </summary>
    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvStdcall)])]
    private static LRESULT StaticWindowProc(HWND window, uint message, WPARAM wParam, LPARAM lParam)
    {
        switch (message)
        {
            case PInvoke.WM_COPYDATA:
                return (LRESULT)HandleCopyData(lParam);
            case PInvoke.WM_CLOSE:
            case PInvoke.WM_DESTROY:
                PInvoke.PostQuitMessage(0);
                return default;
            default:
                return PInvoke.DefWindowProc(window, message, wParam, lParam);
        }
    }

    /// <summary>
    /// Serves one request the way Pageant does: open the mapping named in the
    /// message, read <c>[4-byte length][payload]</c>, write the response back
    /// into the same buffer, and report success through the return value.
    /// </summary>
    private static unsafe nint HandleCopyData(LPARAM lParam)
    {
        var copyData = (COPYDATASTRUCT*)(nint)lParam;
        if (copyData->dwData != PageantCopyDataId)
        {
            Console.Error.WriteLine($"copy data id mismatch: 0x{copyData->dwData:x}");
            return 0;
        }

        string? mappingName = ReadMappingName(copyData->lpData);
        if (string.IsNullOrEmpty(mappingName))
        {
            Console.Error.WriteLine("missing mapping name");
            return 0;
        }

        // "reject" models a Pageant that declines the request without writing
        // anything; the client must notice the zero result and not read the
        // untouched buffer.
        if (s_behavior == "reject")
        {
            return 0;
        }

        // "hang" models a peer that is stuck (or waiting on a prompt) so the
        // client's cancellation path can be exercised from a different process.
        // The markers let the test tell "entered the handler" from "served the
        // request after the client was already gone".
        if (s_behavior == "hang")
        {
            Console.Out.WriteLine("HANGING");
            Console.Out.Flush();
            Thread.Sleep(s_hangMilliseconds);
        }

        HANDLE mapping;
        fixed (char* mappingNamePointer = mappingName)
        {
            mapping = PInvoke.OpenFileMapping((uint)FileMapWrite, false, mappingNamePointer);
        }

        if (mapping.IsNull)
        {
            Console.Error.WriteLine(
                $"OpenFileMapping('{mappingName}') failed ({Marshal.GetLastPInvokeError()})");
            return 0;
        }

        MEMORY_MAPPED_VIEW_ADDRESS view = default;
        try
        {
            view = PInvoke.MapViewOfFile(mapping, FileMapWrite, 0, 0, 0);
            if (view.IsNull)
            {
                Console.Error.WriteLine($"MapViewOfFile failed ({Marshal.GetLastPInvokeError()})");
                return 0;
            }

            Span<byte> buffer = new(view.Value, MappingLength);
            uint requestLength = BinaryPrimitives.ReadUInt32BigEndian(buffer);
            if (requestLength is 0 or > MaxPayloadLength)
            {
                Console.Error.WriteLine($"unusable request length: {requestLength}");
                return 0;
            }

            byte[] request = buffer.Slice(sizeof(uint), (int)requestLength).ToArray();
            byte[] response = s_behavior switch
            {
                "overlong" => BuildRawLengthResponse(9000),
                "zero" => BuildRawLengthResponse(0),
                _ => Frame(BuildResponsePayload(request)),
            };

            response.CopyTo(buffer);

            if (s_behavior == "hang")
            {
                // Printed only after the mapping was opened, read, and written:
                // the client that sent this request has already stopped waiting,
                // so this line is the proof that cancellation did not invalidate
                // the shared buffer.
                Console.Out.WriteLine($"SERVED {mappingName}");
                Console.Out.Flush();
            }

            return 1;
        }
        finally
        {
            if (!view.IsNull)
            {
                _ = PInvoke.UnmapViewOfFile(view);
            }

            _ = PInvoke.CloseHandle(mapping);
        }
    }

    /// <summary>
    /// Reads the NUL-terminated mapping name out of the <c>COPYDATASTRUCT</c>.
    /// The client writes ASCII, whose bytes are also valid UTF-8.
    /// </summary>
    private static unsafe string? ReadMappingName(void* namePointer)
    {
        if (namePointer is null)
        {
            return null;
        }

        ReadOnlySpan<byte> bytes = MemoryMarshal.CreateReadOnlySpanFromNullTerminated((byte*)namePointer);
        return Encoding.ASCII.GetString(bytes);
    }

    private static byte[] BuildResponsePayload(byte[] request)
    {
        return request[0] switch
        {
            MsgRequestIdentities => BuildIdentitiesAnswer(),
            MsgSignRequest => BuildSignResponse(),
            _ => [MsgFailure],
        };
    }

    /// <summary>Writes a response header claiming <paramref name="length"/> bytes.</summary>
    private static byte[] BuildRawLengthResponse(uint length)
    {
        byte[] response = new byte[sizeof(uint)];
        BinaryPrimitives.WriteUInt32BigEndian(response, length);
        return response;
    }

    private static byte[] BuildIdentitiesAnswer()
    {
        var payload = new List<byte> { MsgIdentitiesAnswer };
        WriteUInt32(payload, 1);
        WriteString(payload, s_identityBlob);
        WriteString(payload, "pageant-test-host"u8);
        return [.. payload];
    }

    private static byte[] BuildSignResponse()
    {
        var payload = new List<byte> { MsgSignResponse };
        WriteString(payload, s_signatureBlob);
        return [.. payload];
    }

    private static byte[] BuildIdentityBlob()
    {
        var blob = new List<byte>();
        WriteString(blob, "ssh-ed25519"u8);
        byte[] publicKey = new byte[32];
        for (int i = 0; i < publicKey.Length; i++)
        {
            publicKey[i] = (byte)(i + 1);
        }

        WriteString(blob, publicKey);
        return [.. blob];
    }

    private static byte[] BuildSignatureBlob()
    {
        var blob = new List<byte>();
        WriteString(blob, "ssh-ed25519"u8);
        byte[] signature = new byte[64];
        for (int i = 0; i < signature.Length; i++)
        {
            signature[i] = (byte)(0xA0 + i);
        }

        WriteString(blob, signature);
        return [.. blob];
    }

    private static byte[] Frame(byte[] payload)
    {
        byte[] framed = new byte[sizeof(uint) + payload.Length];
        BinaryPrimitives.WriteUInt32BigEndian(framed, (uint)payload.Length);
        payload.CopyTo(framed, sizeof(uint));
        return framed;
    }

    private static void WriteUInt32(List<byte> buffer, uint value)
    {
        byte[] bytes = new byte[sizeof(uint)];
        BinaryPrimitives.WriteUInt32BigEndian(bytes, value);
        buffer.AddRange(bytes);
    }

    private static void WriteString(List<byte> buffer, ReadOnlySpan<byte> value)
    {
        WriteUInt32(buffer, (uint)value.Length);
        buffer.AddRange(value.ToArray());
    }
}
