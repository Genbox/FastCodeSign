using System.Runtime.InteropServices;
using Genbox.FastCodeSign.Native.MacCodeSign.Native.Enums;

// ReSharper disable InconsistentNaming

namespace Genbox.FastCodeSign.Native.MacCodeSign.Native;

internal static partial class MacNative
{
    private const string CoreFoundation = "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation";
    private const string Security = "/System/Library/Frameworks/Security.framework/Security";
    private const string LibSystem = "/usr/lib/libSystem.B.dylib";

    private static readonly IntPtr _sec = dlopen(Security, 0x1 | 0x4); // RTLD_LAZY|RTLD_LOCAL

    // Returns the CFTypeRef *value* stored in the data symbol.
    private static IntPtr GetCfConst(string symbol)
    {
        if (_sec == IntPtr.Zero)
            throw new InvalidOperationException("dlopen(Security) failed");

        IntPtr symAddr = dlsym(_sec, symbol);

        if (symAddr == IntPtr.Zero)
            throw new InvalidOperationException($"dlsym {symbol} failed");

        // symAddr points to a CFTypeRef variable; read the CFTypeRef stored there.
        return Marshal.ReadIntPtr(symAddr);
    }

    internal static readonly IntPtr kSecImportExportPassphrase = GetCfConst("kSecImportExportPassphrase");
    internal static readonly IntPtr kSecImportItemIdentity = GetCfConst("kSecImportItemIdentity");
    internal static readonly IntPtr kSecCodeSignerIdentity = GetCfConst("kSecCodeSignerIdentity");

    [LibraryImport(CoreFoundation)]
    internal static partial void CFRelease(IntPtr cf);

    [LibraryImport(CoreFoundation, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial IntPtr CFStringCreateWithCString(IntPtr alloc, string cStr, CFStringEncoding encoding);

    [LibraryImport(CoreFoundation)]
    internal static partial IntPtr CFURLCreateFromFileSystemRepresentation(IntPtr allocator, [In]byte[] buffer, nint bufLen, [MarshalAs(UnmanagedType.Bool)]bool isDirectory);

    [LibraryImport(CoreFoundation)]
    internal static partial IntPtr CFDictionaryCreateMutable(IntPtr allocator, nint capacity, IntPtr keyCallbacks, IntPtr valueCallbacks);

    [LibraryImport(CoreFoundation)]
    internal static partial void CFDictionarySetValue(IntPtr dict, IntPtr key, IntPtr value);

    [LibraryImport(CoreFoundation)]
    internal static partial IntPtr CFDataCreate(IntPtr allocator, [In]byte[] bytes, nint length);

    [LibraryImport(CoreFoundation)]
    internal static partial nint CFArrayGetCount(IntPtr cfArray);

    [LibraryImport(CoreFoundation)]
    internal static partial IntPtr CFArrayGetValueAtIndex(IntPtr cfArray, nint idx);

    [LibraryImport(CoreFoundation)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool CFDictionaryGetValueIfPresent(IntPtr dict, IntPtr key, out IntPtr value);

    [LibraryImport(Security)]
    internal static partial int SecStaticCodeCreateWithPath(IntPtr path, SecCSFlags flags, out IntPtr staticCode);

    [LibraryImport(Security)]
    internal static partial int SecCodeSignerCreate(IntPtr parameters, SecCSFlags flags, out IntPtr signer);

    [LibraryImport(Security)]
    internal static partial int SecCodeSignerAddSignatureWithErrors(IntPtr signer, IntPtr staticCode, SecCSFlags flags, out IntPtr cfError /* CFErrorRef */);

    [LibraryImport(Security)]
    internal static unsafe partial int SecPKCS12Import(IntPtr pkcs12_data, IntPtr options, IntPtr* items);

    [LibraryImport(LibSystem, StringMarshalling = StringMarshalling.Utf8)]
    private static partial IntPtr dlopen(string path, int mode);

    [LibraryImport(LibSystem, StringMarshalling = StringMarshalling.Utf8)]
    private static partial IntPtr dlsym(IntPtr handle, string symbol);
}