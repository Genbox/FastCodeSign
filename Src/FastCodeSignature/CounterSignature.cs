using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Genbox.FastCodeSignature;

public sealed record CounterSignature(X509Certificate2 Certificate, HashAlgorithmName HashAlgorithm, DateTime TimeStamp);