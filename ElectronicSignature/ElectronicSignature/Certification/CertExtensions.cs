using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
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

    /// <summary>
    /// Converts the given AsymmetricKeyParameter to its Base64-encoded string representation.
    /// </summary>
    /// <param name="key">The AsymmetricKeyParameter instance to be converted.</param>
    /// <returns>A Base64-encoded string representation of the given key.</returns>
    /// <remarks>
    /// This method checks if the given key is a private or a public key, then creates the
    /// appropriate key information object and encodes it to a byte array. Finally, it returns
    /// the Base64-encoded string representation of the byte array.
    /// </remarks>
    public static string ConvertKeyToBase64(this AsymmetricKeyParameter key)
    {
        if(key.IsPrivate)
        {
            var privateKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(key);
            var privateKeyBytes = privateKeyInfo.ToAsn1Object().GetEncoded();
            return Convert.ToBase64String(privateKeyBytes);
        }

        var publicKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(key);
        var publicKeyBytes = publicKeyInfo.GetDerEncoded();

        return Convert.ToBase64String(publicKeyBytes);
    }

    /// <summary>
    /// Converts a Base64-encoded string representation of an asymmetric key to an AsymmetricKeyParameter instance.
    /// </summary>
    /// <param name="keyBase64">The Base64-encoded string representation of the asymmetric key.</param>
    /// <returns>An AsymmetricKeyParameter instance representing the given key.</returns>
    /// <remarks>
    /// This method tries to create a public key from the given Base64-encoded string.
    /// If it fails due to a CryptographicException, it assumes the key is a private key
    /// and tries to create a private key instead. If successful, it returns the created
    /// AsymmetricKeyParameter instance.
    /// </remarks>
    public static AsymmetricKeyParameter ConvertKeyFromBase64(this string keyBase64)
    {
        var keyBytes = Convert.FromBase64String(keyBase64);

        AsymmetricKeyParameter key;
        try
        {
            key = PublicKeyFactory.CreateKey(keyBytes);
        }
        catch (CryptographicException)
        {
            key = PrivateKeyFactory.CreateKey(keyBytes);
        }

        return key;
    }

    /// <summary>
    /// Converts the given input string to its binary representation using UTF-8 encoding.
    /// </summary>
    /// <param name="inputString">The input string to be converted to binary.</param>
    /// <returns>A string containing the binary representation of the input string.</returns>
    /// <remarks>
    /// This method first converts the input string to a byte array using UTF-8 encoding.
    /// Then, it constructs a binary string by iterating through each byte and converting it to its binary representation
    /// with 8-bit padding. Finally, it returns the concatenated binary string.
    /// </remarks>
    public static string ToBinary(this string inputString)
    {
        var bytes = Encoding.UTF8.GetBytes(inputString);

        var binaryString = bytes.Aggregate("", (current, b) => current + Convert.ToString(b, 2).PadLeft(8, '0'));

        return binaryString;
    }

    /// <summary>
    /// Converts the given input bytes to its binary representation.
    /// </summary>
    /// <param name="inputBytes">The input bytes to be converted to binary.</param>
    /// <returns>A string containing the binary representation of the input bytes.</returns>
    /// <remarks>
    /// It constructs a binary string by iterating through each byte and converting it to its binary representation
    /// with 8-bit padding. Finally, it returns the concatenated binary string.
    /// </remarks>
    public static string ToBinary(this byte[] inputBytes)
    {
        var binaryString = inputBytes.Aggregate("", (current, b) => current + Convert.ToString(b, 2).PadLeft(8, '0'));

        return binaryString;
    }
}