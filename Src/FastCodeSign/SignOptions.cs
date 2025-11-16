using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Genbox.FastCodeSign;

public sealed class SignOptions
{
    /// <summary>The certificate to sign with</summary>
    public required X509Certificate2 Certificate { get; set; }

    /// <summary>The private key to use. You need to set this if you want to provide a custom private key implementation, such as using a HSM.</summary>
    public AsymmetricAlgorithm? PrivateKey { get; set; }

    /// <summary>The hash algorithm to use when creating the signature</summary>
    public HashAlgorithmName HashAlgorithm { get; set; } = HashAlgorithmName.SHA256;

    /// <summary>A bool indicating if the underlying key provider can ask for PIN or not</summary>
    public bool Silent { get; set; } = true;
}