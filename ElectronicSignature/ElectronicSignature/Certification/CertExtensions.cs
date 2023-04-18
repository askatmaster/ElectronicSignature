using System.Security.Cryptography.X509Certificates;
using System.Text;
namespace ElectronicSignature.Certification;

public static class CertExtensions
{
    /// <summary>
    /// Retrieves a private X.509 certificate from a file path with the specified password.
    /// </summary>
    /// <param name="certFilePath">The file path of the certificate.</param>
    /// <param name="password">The password to access the certificate.</param>
    /// <returns>A <see cref="X509Certificate2"/> object that represents the private certificate.</returns>
    public static X509Certificate2 GetPrivateCert(this string certFilePath, string? password)
    {
        return new X509Certificate2(certFilePath, password, X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.Exportable);
    }

    /// <summary>
    /// Retrieves a private X.509 certificate from a byte array with the specified password.
    /// </summary>
    /// <param name="cert">The byte array of the certificate.</param>
    /// <param name="password">The password to access the certificate.</param>
    /// <returns>A <see cref="X509Certificate2"/> object that represents the private certificate.</returns>
    public static X509Certificate2 GetPrivateCert(this byte[] cert, string? password)
    {
        return new X509Certificate2(cert, password, X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.Exportable);
    }

    /// <summary>
    /// Retrieves a public X.509 certificate from a file path.
    /// </summary>
    /// <param name="certFile">The file path of the certificate.</param>
    /// <returns>A <see cref="X509Certificate2"/> object that represents the public certificate.</returns>
    public static X509Certificate2 GetPublicCert(this string certFile)
    {
        return new X509Certificate2(certFile);
    }

    /// <summary>
    /// Retrieves a public X.509 certificate from a byte array.
    /// </summary>
    /// <param name="cert">The byte array of the certificate.</param>
    /// <returns>A <see cref="X509Certificate2"/> object that represents the public certificate.</returns>
    public static X509Certificate2 GetPublicCert(this byte[] cert)
    {
        return new X509Certificate2(cert);
    }

    /// <summary>
    /// Retrieves a public X.509 certificate from a Base64-encoded string.
    /// </summary>
    /// <param name="base64String">The Base64-encoded string of the certificate.</param>
    /// <returns>A <see cref="X509Certificate2"/> object that represents the public certificate.</returns>
    public static X509Certificate2 GetPublicCertWithBase64(this string base64String)
    {
        return new X509Certificate2(Encoding.UTF8.GetBytes(base64String));
    }

    /// <summary>
    /// Retrieves a private X.509 certificate from a Base64-encoded string with the specified password.
    /// </summary>
    /// <param name="base64PrivateKey">The Base64-encoded string of the private key.</param>
    /// <param name="password">The password to access the certificate.</param>
    /// <returns>A <see cref="X509Certificate2"/> object that represents the private certificate.</returns>
    public static X509Certificate2 GetPrivateCertFromBase64(this string base64PrivateKey, string password)
    {
        return new X509Certificate2(Convert.FromBase64String(base64PrivateKey), password, X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.Exportable);
    }

    /// <summary>
    /// Determines if the given <paramref name="algorithm"/> is an RSA algorithm.
    /// </summary>
    /// <param name="algorithm">The cryptography algorithm to check.</param>
    /// <returns>True if the algorithm is RSA, otherwise false.</returns>
    public static bool IsRsaAlgorithm(this CryptographyAlgorithm algorithm)
    {
        var algorithmName = algorithm.ToString();

        return  algorithmName[^3..].ToLower() == "rsa";
    }

    /// <summary>
    /// Determines if the given <paramref name="algorithmName"/> is an RSA algorithm.
    /// </summary>
    /// <param name="algorithmName">The name of the cryptography algorithm to check.</param>
    /// <returns>True if the algorithm is RSA, otherwise false.</returns>
    public static bool IsRsaAlgorithm(this string algorithmName)
    {
        return algorithmName[^3..].ToLower() == "rsa";
    }

    /// <summary>
    /// Determines if the given <paramref name="algorithm"/> is an ECDSA algorithm.
    /// </summary>
    /// <param name="algorithm">The cryptography algorithm to check.</param>
    /// <returns>True if the algorithm is ECDSA, otherwise false.</returns>
    public static bool IsECDSAAlgorithm(this CryptographyAlgorithm algorithm)
    {
        var algorithmName = algorithm.ToString();

        return algorithmName[^5..].ToLower() == "ecdsa";
    }

    /// <summary>
    /// Determines if the given <paramref name="algorithmName"/> is an ECDSA algorithm.
    /// </summary>
    /// <param name="algorithmName">The name of the cryptography algorithm to check.</param>
    /// <returns>True if the algorithm is ECDSA, otherwise false.</returns>
    public static bool IsECDSAAlgorithm(this string algorithmName)
    {
        return algorithmName[^5..].ToLower() == "ecdsa";
    }
}