using Genbox.FastCodeSign.Native.MacCodeSign;

namespace Genbox.Tools.Mac.CreateFiles;

// This tool creates signed executables files for iOS.

internal static class Program
{
    private static void Main()
    {
        if (!OperatingSystem.IsMacOS())
            throw new PlatformNotSupportedException("This tool only runs on MacOS");

        byte[] certBytes = File.ReadAllBytes("FastCodeSign.pfx");

        SignFile("MachO/macho_unsigned.dat", "MachO/macho_signed.dat", certBytes);
    }

    private static void SignFile(string unsigned, string signed, byte[] certBytes)
    {
        Console.WriteLine($"Signing {unsigned}");
        File.Copy(unsigned, signed, true);
        MacCodeSigner.SignFile(unsigned, certBytes, "password");
    }
}