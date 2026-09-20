// Translated from the Pageant client code in libssh2 src/agent.c.
// See LICENSE and THIRD-PARTY-NOTICES.md for project and upstream terms.
/*
 * Code to talk to Pageant was taken from PuTTY.
 *
 * Portions copyright Robert de Bath, Joris van Rantwijk, Delian
 * Delchev, Andreas Schultz, Jeroen Massar, Wez Furlong, Nicolas
 * Barry, Justin Bradford, Ben Harris, Malcolm Smith, Ahmad Khalifa,
 * Markus Kuhn, Colin Watson, and CORE SDI S.A.
 */

using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;

using Windows.Win32;
using Windows.Win32.Foundation;
using Windows.Win32.System.DataExchange;
using Windows.Win32.System.Memory;

namespace LibSsh2CS.Agent;

/// <summary>
/// The default <see cref="IPageantWindowChannel"/>: talks to a real Pageant
/// window through <c>WM_COPYDATA</c> and a thread-scoped file mapping. Parity
/// with <c>agent_transact_pageant</c> (<c>agent.c:352-417</c>).
/// </summary>
/// <remarks>
/// <para>
/// <b>Mapping lifetime.</b> Unlike a socket, nothing is kept open between
/// transactions. Every round trip creates the mapping named
/// <c>PageantRequest&lt;thread id&gt;</c>, maps a view, writes the request,
/// sends the message, reads the response, and releases both the view and the
/// handle in a <c>finally</c> — on success, on rejection, and on any mapping
/// failure. Those resources are released only after the send returns, because
/// Pageant keeps a reference to the mapping until its window procedure
/// returns. The response is copied into managed memory before the release, so
/// no receiver can ever be left pointing at freed memory.
/// </para>
/// <para>
/// <b>Completion-bound send.</b> <see cref="Transact"/> has no native timeout:
/// the send returns only after the receiver's window procedure has finished
/// with the message (or the window is gone), which is what makes the cleanup
/// below safe. A message that was already delivered cannot be recalled, so a
/// timed-out send would return while Pageant could still be reaching for the
/// mapping. The caller's tolerance for a slow Pageant lives in
/// <see cref="PageantAgentTransport"/> instead, which bounds only its own wait.
/// </para>
/// <para>
/// <b>Cancellation.</b> A caller that needs to stop waiting sooner cancels the
/// managed wait in <see cref="PageantAgentTransport"/>, which releases the
/// caller while this call keeps running on its worker thread until the send
/// returns. Pageant may still act on a request it already received.
/// </para>
/// <para>
/// <b>Thread affinity.</b> The mapping name embeds
/// <c>GetCurrentThreadId</c>, so it must be computed on the thread that
/// performs the round trip. Callers must not move the operation between threads
/// mid-call.
/// </para>
/// <para>
/// <b>Isolation.</b> The window class and title default to <c>Pageant</c>, the
/// values a real Pageant registers. The internal constructor overrides them so
/// the IPC integration tests can address their own fixture window instead of
/// the developer's running Pageant.
/// </para>
/// <para>
/// <b>Interop.</b> The Windows entry points and their types come from CsWin32
/// (<c>Windows.Win32.PInvoke</c>), which declares them as source-generated
/// <c>LibraryImport</c> methods. Every call is blittable, and the assembly
/// disables runtime marshalling outright, so nothing here needs the runtime
/// marshaler. This is the only type in the library that touches native memory,
/// and the pointers it hands to Win32 are the pinned mapping name and the
/// mapped view itself.
/// </para>
/// </remarks>
[SupportedOSPlatform("windows")]
[SuppressMessage("Platform Compatibility", "CA1416:Validate platform compatibility", Justification = "The generated entry points name the Windows version each one first appeared in — 5.0 for FindWindow and CloseHandle, 5.1.2600 for GetCurrentThreadId and the mapping calls. Those distinctions say nothing about this client: no version of the .NET runtime this library targets exists on anything older, and the gate the library really depends on is the unversioned OperatingSystem.IsWindows() check in PageantAgentTransport.TryCreate.")]
internal sealed unsafe class PageantWindowChannel : IPageantWindowChannel
{
    /// <summary>The window class a real Pageant registers.</summary>
    internal const string DefaultWindowClass = "Pageant";

    /// <summary>The window title a real Pageant registers.</summary>
    internal const string DefaultWindowTitle = "Pageant";

    private readonly string _windowClass;
    private readonly string _windowTitle;

    /// <summary>
    /// Creates a channel that talks to the real Pageant window. Constructing
    /// the channel does not call any native API.
    /// </summary>
    public PageantWindowChannel()
        : this(DefaultWindowClass, DefaultWindowTitle)
    {
    }

    /// <summary>
    /// Creates a channel bound to an explicit window identity. Used by tests to
    /// address a fixture window instead of the developer's Pageant; production
    /// code uses the parameterless constructor.
    /// </summary>
    /// <param name="windowClass">Window class to look up.</param>
    /// <param name="windowTitle">Window title to look up.</param>
    internal PageantWindowChannel(string windowClass, string windowTitle)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(windowClass);
        ArgumentException.ThrowIfNullOrWhiteSpace(windowTitle);

        _windowClass = windowClass;
        _windowTitle = windowTitle;
    }

    /// <inheritdoc/>
    public nint FindWindow()
        => PInvoke.FindWindow(_windowClass, _windowTitle);

    /// <inheritdoc/>
    public byte[] Transact(ReadOnlyMemory<byte> requestPayload)
    {
        // Defensive bound: this is the memory-safety boundary, so the limit is
        // enforced here as well as in the transport.
        if (requestPayload.Length > PageantIpc.MaxPayloadLength)
        {
            throw new SshException(SshErrorCode.Inval,
                $"Pageant request too long ({requestPayload.Length + sizeof(uint)} > {PageantIpc.MaxMessageLength})");
        }

        HWND window = PInvoke.FindWindow(_windowClass, _windowTitle);
        if (window.IsNull)
        {
            throw new SshException(SshErrorCode.AgentProtocol, "found no pageant");
        }

        // "PageantRequest%08x" with this thread's id (agent.c:365-366), which
        // is why the name is built here rather than handed in.
        string mappingName = PageantIpc.MappingName(PInvoke.GetCurrentThreadId());

        // The mapping name is pure ASCII, so its UTF-8 bytes are also its
        // ANSI bytes — which is what Pageant reads out of COPYDATASTRUCT. The
        // array's trailing byte is the NUL terminator Pageant needs: nothing
        // writes it, so it stays zero.
        byte[] nameBytes = new byte[Encoding.ASCII.GetByteCount(mappingName) + 1];
        Encoding.ASCII.GetBytes(mappingName, nameBytes);

        // Pageant reads the name while it serves the message, so it is pinned
        // for the whole round trip rather than copied into an allocation this
        // type would have to free on every exit path.
        fixed (byte* namePointer = nameBytes)
        {
            var copyData = new COPYDATASTRUCT
            {
                dwData = PageantIpc.CopyDataId,
                cbData = (uint)nameBytes.Length,
                lpData = namePointer,
            };

            HANDLE fileMapping = default;
            MEMORY_MAPPED_VIEW_ADDRESS view = default;
            try
            {
                fileMapping = CreateMapping(mappingName);
                view = MapRequestView(fileMapping);

                // [4-byte big-endian length][payload] — the layout Pageant
                // reads (_libssh2_store_str in agent.c:388).
                WriteRequest(view, requestPayload);

                // Completion-bound by design: Pageant may prompt for a
                // passphrase or a signing confirmation, and the mapping stays
                // valid for the whole time the receiver can reach it. The
                // caller's wait is bounded in PageantAgentTransport, which
                // abandons this worker rather than invalidating its state.
                // The message payload: Pageant reads the mapping name out of
                // this COPYDATASTRUCT, so it has to stay addressable until the
                // send returns. The struct is a local of an unmanaged type, so
                // its address is stable without pinning it.
                void* copyDataPointer = &copyData;
                LRESULT sendResult = PInvoke.SendMessage(
                    window,
                    PInvoke.WM_COPYDATA,
                    default,
                    (LPARAM)(IntPtr)copyDataPointer);

                if (sendResult == 0)
                {
                    // Pageant returns 0 for a request it will not serve (for
                    // example an unexpected dwData or a refused key); a window
                    // that vanished before the send reports the same, and the
                    // buffer is left untouched rather than parsed.
                    throw new SshException(SshErrorCode.AgentProtocol, "pageant rejected the request");
                }

                return ReadResponse(view);
            }
            finally
            {
                if (!view.IsNull)
                {
                    _ = PInvoke.UnmapViewOfFile(view);
                }

                if (!fileMapping.IsNull)
                {
                    _ = PInvoke.CloseHandle(fileMapping);
                }
            }
        }
    }

    /// <summary>
    /// Creates the page-file-backed mapping Pageant serves the request from.
    /// </summary>
    private static HANDLE CreateMapping(string mappingName)
    {
        HANDLE fileMapping;
        fixed (char* namePointer = mappingName)
        {
            fileMapping = PInvoke.CreateFileMapping(
                HANDLE.INVALID_HANDLE_VALUE,
                null,
                PAGE_PROTECTION_FLAGS.PAGE_READWRITE,
                0,
                PageantIpc.MaxMessageLength,
                namePointer);
        }

        if (fileMapping.IsNull)
        {
            throw new SshException(SshErrorCode.AgentProtocol,
                $"failed setting up pageant filemap (Win32 error {Marshal.GetLastPInvokeError()})");
        }

        if ((WIN32_ERROR)Marshal.GetLastPInvokeError() == WIN32_ERROR.ERROR_ALREADY_EXISTS)
        {
            // The name belongs to somebody else; sharing it would mean reading
            // or writing another caller's request buffer. The handle returned
            // above is still valid even in this case, so release it before
            // failing — the caller's cleanup only runs for handles it received.
            _ = PInvoke.CloseHandle(fileMapping);
            throw new SshException(SshErrorCode.AgentProtocol,
                $"failed setting up pageant filemap ('{mappingName}' is already in use)");
        }

        return fileMapping;
    }

    /// <summary>Maps the writable view the request is copied into.</summary>
    private static MEMORY_MAPPED_VIEW_ADDRESS MapRequestView(HANDLE fileMapping)
    {
        MEMORY_MAPPED_VIEW_ADDRESS view = PInvoke.MapViewOfFile(
            fileMapping, FILE_MAP.FILE_MAP_WRITE, 0, 0, 0);

        if (view.IsNull)
        {
            throw new SshException(SshErrorCode.AgentProtocol,
                $"failed to open pageant filemap for writing (Win32 error {Marshal.GetLastPInvokeError()})");
        }

        return view;
    }

    /// <summary>
    /// Writes <c>[4-byte big-endian length][payload]</c> into the mapping — the
    /// layout Pageant reads (<c>_libssh2_store_str</c> in <c>agent.c:388</c>).
    /// </summary>
    private static void WriteRequest(MEMORY_MAPPED_VIEW_ADDRESS view, ReadOnlyMemory<byte> requestPayload)
    {
        Span<byte> mapping = new(view.Value, PageantIpc.MaxMessageLength);
        BinaryPrimitives.WriteUInt32BigEndian(mapping, (uint)requestPayload.Length);
        requestPayload.Span.CopyTo(mapping[sizeof(uint)..]);
    }

    /// <summary>
    /// Copies the response payload out of the mapping after validating its
    /// length. libssh2 accepts anything up to <c>PAGEANT_MAX_MSGLEN</c> after
    /// the prefix and returns success even for a zero-byte response
    /// (<c>agent.c:394-410</c>); both would either read past the mapping or
    /// hand the agent layer an unusable message, so they are rejected here.
    /// </summary>
    private static byte[] ReadResponse(MEMORY_MAPPED_VIEW_ADDRESS view)
    {
        Span<byte> mapping = new(view.Value, PageantIpc.MaxMessageLength);
        uint responseLength = BinaryPrimitives.ReadUInt32BigEndian(mapping);

        if (responseLength is 0 or > (uint)PageantIpc.MaxPayloadLength)
        {
            throw new SshException(SshErrorCode.AgentProtocol,
                $"pageant returned an invalid response length ({responseLength} bytes)");
        }

        return mapping.Slice(sizeof(uint), (int)responseLength).ToArray();
    }
}
