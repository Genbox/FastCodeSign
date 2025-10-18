using System.Text;
using Genbox.FastCodeSign.Native.MacCodeSign.Native.Enums;
using static Genbox.FastCodeSign.Native.MacCodeSign.Native.MacNative;

namespace Genbox.FastCodeSign.Native.MacCodeSign;

public static class MacCodeSign
{
    public static unsafe void SignFile(string path, byte[] pkcs12Bytes, string password)
    {
        if (!File.Exists(path))
            throw new FileNotFoundException(path);

        IntPtr pkcs12Data = IntPtr.Zero;
        IntPtr importOptions = IntPtr.Zero;
        IntPtr importItems = IntPtr.Zero;
        IntPtr cfUrl = IntPtr.Zero;
        IntPtr staticCode = IntPtr.Zero;
        IntPtr signerParams = IntPtr.Zero;
        IntPtr signer = IntPtr.Zero;
        IntPtr cfError = IntPtr.Zero;

        try
        {
            pkcs12Data = CFDataCreate(IntPtr.Zero, pkcs12Bytes, pkcs12Bytes.Length);
            importOptions = CFDictionaryCreateMutable(IntPtr.Zero, 1, IntPtr.Zero, IntPtr.Zero);

            using CfString pass = new CfString(password);
            CFDictionarySetValue(importOptions, kSecImportExportPassphrase, pass.Handle);

            int status = SecPKCS12Import(pkcs12Data, importOptions, &importItems);
            ThrowIfError(status, "SecPKCS12Import");

            //Grab first identity from the array of dictionaries
            nint count = CFArrayGetCount(importItems);
            if (count == 0)
                throw new InvalidOperationException("PKCS#12 contained no identities");

            IntPtr dict0 = CFArrayGetValueAtIndex(importItems, 0);
            if (!CFDictionaryGetValueIfPresent(dict0, kSecImportItemIdentity, out IntPtr identity) || identity == IntPtr.Zero)
                throw new InvalidOperationException("Unable to extract SecIdentity from PKCS#12");

            // Create SecStaticCodeRef for the file
            byte[] bytes = Encoding.UTF8.GetBytes(path);
            cfUrl = CFURLCreateFromFileSystemRepresentation(IntPtr.Zero, bytes, bytes.Length, false);

            status = SecStaticCodeCreateWithPath(cfUrl, SecCSFlags.kSecCSDefaultFlags, out staticCode);
            ThrowIfError(status, "SecStaticCodeCreateWithPath");

            // Build signer parameter dictionary
            signerParams = CFDictionaryCreateMutable(IntPtr.Zero, 3, IntPtr.Zero, IntPtr.Zero);

            CFDictionarySetValue(signerParams, kSecCodeSignerIdentity, identity);

            // Create signer
            status = SecCodeSignerCreate(signerParams, SecCSFlags.kSecCSDefaultFlags, out signer);
            ThrowIfError(status, "SecCodeSignerCreate");

            // Add signature
            status = SecCodeSignerAddSignatureWithErrors(signer, staticCode, SecCSFlags.kSecCSDefaultFlags, out cfError);

            if (status != 0)
            {
                string err = $"SecCodeSignerAddSignatureWithErrors failed: 0x{status:X8}";

                if (cfError != IntPtr.Zero)
                    err += $" (CFError {cfError})";

                throw new InvalidOperationException(err);
            }
        }
        finally
        {
            // release in reverse acquisition order
            if (cfError != IntPtr.Zero) CFRelease(cfError);
            if (signer != IntPtr.Zero) CFRelease(signer);
            if (signerParams != IntPtr.Zero) CFRelease(signerParams);
            if (staticCode != IntPtr.Zero) CFRelease(staticCode);
            if (cfUrl != IntPtr.Zero) CFRelease(cfUrl);
            if (importItems != IntPtr.Zero) CFRelease(importItems);
            if (importOptions != IntPtr.Zero) CFRelease(importOptions);
            if (pkcs12Data != IntPtr.Zero) CFRelease(pkcs12Data);
        }
    }

    private static void ThrowIfError(int status, string api)
    {
        if (status != 0)
            throw new InvalidOperationException($"{api} failed with OSStatus=0x{status:X8}");
    }

    private sealed class CfString(string value) : IDisposable
    {
        public IntPtr Handle { get; } = CFStringCreateWithCString(IntPtr.Zero, value, CFStringEncoding.kCFStringEncodingUTF8);

        public void Dispose()
        {
            if (Handle != IntPtr.Zero)
                CFRelease(Handle);
        }
    }
}