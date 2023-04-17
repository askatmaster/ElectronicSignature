using System.Security.Cryptography.X509Certificates;
using System.Text;
namespace ElectronicSignature.Certification;

public static class CertExtensions
{
    public static X509Certificate2 GetPrivateCert(this string certFilePath, string? password)
    {
        return new X509Certificate2(certFilePath, password, X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.Exportable);
    }

    public static X509Certificate2 GetPrivateCert(this byte[] cert, string? password)
    {
        return new X509Certificate2(cert, password, X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.Exportable);
    }

    public static X509Certificate2 GetPublicCert(this string certFile)
    {
        return new X509Certificate2(certFile);
    }

    public static X509Certificate2 GetPublicCert(this byte[] cert)
    {
        return new X509Certificate2(cert);
    }

    public static X509Certificate2 GetPublicCertWithBase64(this string base64String)
    {
        return new X509Certificate2(Encoding.UTF8.GetBytes(base64String));
    }

    public static X509Certificate2 GetPrivateCertFromBase64(this string base64PrivateKey, string password)
    {
        return new X509Certificate2(Convert.FromBase64String(base64PrivateKey), password, X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.Exportable);
    }

    public static bool IsRsaAlgorithm(this CryptographyAlgorithm algorithm)
    {
        var algorithmName = algorithm.ToString();

        return  algorithmName[^3..].ToLower() == "rsa";
    }

    public static bool IsRsaAlgorithm(this string algorithmName)
    {
        return  algorithmName[^3..].ToLower() == "rsa";
    }

    public static bool IsECDSAAlgorithm(this CryptographyAlgorithm algorithm)
    {
        var algoritmName = algorithm.ToString();

        return  algoritmName[^5..].ToLower() == "ecdsa";
    }

    public static bool IsECDSAAlgorithm(this string algoritmName)
    {
        return  algoritmName[^5..].ToLower() == "ecdsa";
    }
}