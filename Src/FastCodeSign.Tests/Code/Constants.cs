using System.Security.Cryptography.X509Certificates;

namespace Genbox.FastCodeSign.Tests.Code;

internal static class Constants
{
    internal const string FilesDir = "../../../../../Files/";
    internal static X509Certificate2 GetCert() => X509CertificateLoader.LoadPkcs12FromFile(Path.Combine(FilesDir, "FastCodeSign.pfx"), "password");
}