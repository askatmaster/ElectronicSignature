using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
namespace ElectronicSignature.Certification;

public static class PemExtensions
{
    /// <summary>
    /// Writes the given key to a PEM file with the specified file name.
    /// </summary>
    /// <param name="key">The key object to be written to the PEM file. Can be either a public or private key.</param>
    /// <param name="fileName">The name of the file where the key will be saved in PEM format.</param>
    public static void ToPemFile(this object key, string fileName)
    {
        using (var privateKeyWriter = new StreamWriter(fileName))
        {
            var pemWriter = new PemWriter(privateKeyWriter);
            pemWriter.WriteObject(key);
        }
    }

    /// <summary>
    /// Writes the given AsymmetricCipherKeyPair's private and public keys to a PEM file with the specified file name.
    /// </summary>
    /// <param name="key">The AsymmetricCipherKeyPair object containing the private and public keys to be written to the PEM file.</param>
    /// <param name="fileName">The name of the file where the private and public keys will be saved in PEM format.</param>
    public static void ToPemFile(this AsymmetricCipherKeyPair key, string fileName)
    {
        using (var privateKeyWriter = new StreamWriter(fileName))
        {
            var pemWriter = new PemWriter(privateKeyWriter);
            pemWriter.WriteObject(key.Private);
            pemWriter.WriteObject(key.Public);
        }
    }

    /// <summary>
    /// Reads a PEM file and returns the object of the specified type.
    /// </summary>
    /// <typeparam name="T">The type of the object to be returned. Should match the type of the object stored in the PEM file.</typeparam>
    /// <param name="pemFilePath">The file path of the PEM file to be read.</param>
    /// <returns>The object of type T read from the PEM file.</returns>
    public static T GetFromPemFile<T>(this string pemFilePath)
    {
        using (var reader = new StreamReader(pemFilePath))
        {
            var pemReader = new PemReader(reader);
            return (T)pemReader.ReadObject();
        }
    }

    /// <summary>
    /// Reads a PEM file and returns a Pkcs10CertificationRequest object.
    /// </summary>
    /// <param name="pemFilePath">The file path of the PEM file containing the CSR.</param>
    /// <returns>The Pkcs10CertificationRequest object read from the PEM file.</returns>
    public static Pkcs10CertificationRequest GetCSRPemFile(this string pemFilePath)
    {
        using (var reader = new StreamReader(pemFilePath))
        {
            var pemReader = new PemReader(reader);
            return (Pkcs10CertificationRequest)pemReader.ReadObject();
        }
    }

    /// <summary>
    /// Reads a PEM file and returns an AsymmetricCipherKeyPair object.
    /// </summary>
    /// <param name="pemFilePath">The file path of the PEM file containing the key pair.</param>
    /// <returns>The AsymmetricCipherKeyPair object read from the PEM file.</returns>
    public static AsymmetricCipherKeyPair GetKeyPairFromPem(this string pemFilePath)
    {
        using (var reader = new StreamReader(pemFilePath))
        {
            var pemReader = new PemReader(reader);
            return (AsymmetricCipherKeyPair)pemReader.ReadObject();
        }
    }

    /// <summary>
    /// Reads a PEM file and returns an AsymmetricKeyParameter object representing the private key.
    /// </summary>
    /// <param name="privateKeyPath">The file path of the PEM file containing the private key.</param>
    /// <returns>The AsymmetricKeyParameter object representing the private key read from the PEM file.</returns>
    /// <exception cref="InvalidOperationException">Thrown when the provided file does not contain a private key.</exception>
    public static AsymmetricKeyParameter GetPrivateKeyFromPem(this string privateKeyPath)
    {
        using (var reader = new StreamReader(privateKeyPath))
        {
            var pemReader = new PemReader(reader);
            var obj = pemReader.ReadObject();

            if (obj is AsymmetricCipherKeyPair keyPair)
                return keyPair.Private;

            throw new InvalidOperationException("The provided file does not contain a private key.");
        }
    }

    /// <summary>
    /// Reads a PEM file and returns an AsymmetricKeyParameter object representing the public key.
    /// </summary>
    /// <param name="publicKeyPath">The file path of the PEM file containing the public key.</param>
    /// <returns>The AsymmetricKeyParameter object representing the public key read from the PEM file.</returns>
    /// <exception cref="Exception">Thrown when the provided file contains a private key instead of a public key.</exception>
    /// <exception cref="InvalidOperationException">Thrown when the provided file does not contain a public key.</exception>
    public static AsymmetricKeyParameter GetPublicKeyFromPem(this string publicKeyPath)
    {
        using (var reader = new StreamReader(publicKeyPath))
        {
            var pemReader = new PemReader(reader);
            var obj = pemReader.ReadObject();

            if (obj is RsaKeyParameters keyPair)
            {
                if(keyPair.IsPrivate)
                    throw new Exception("The provided file contain a private key instead of a public key.");

                return keyPair;
            }

            throw new InvalidOperationException("The provided file does not contain a public key.");
        }
    }

    /// <summary>
    /// Imports a compressed ECDSA public key from a PEM-formatted string using a specified curve.
    /// </summary>
    /// <param name="pem">A string containing the PEM-formatted compressed ECDSA public key.</param>
    /// <param name="curveName">The ECNamedCurve to be used for the imported key. Default is secp256k1.</param>
    /// <returns>An ECPublicKeyParameters instance representing the imported ECDSA public key.</returns>
    /// <exception cref="ArgumentException">Thrown when the provided PEM object type is not 'EC PUBLIC KEY'.</exception>
    /// <remarks>
    /// This method reads the PEM-formatted string and expects an 'EC PUBLIC KEY' object.
    /// It retrieves the specified named curve parameters and decodes the point from the PEM object's content.
    /// Finally, it creates and returns an ECPublicKeyParameters instance using the decoded point and the domain parameters.
    /// </remarks>
    public static ECPublicKeyParameters GetCompressedECDSAPublicKeyFromPem(this string pem, ECNamedCurve curveName = ECNamedCurve.secp256k1)
    {
        using (TextReader textReader = new StringReader(pem))
        {
            var pemReader = new PemReader(textReader);
            var pemObject = pemReader.ReadPemObject();

            if (pemObject.Type != "EC PUBLIC KEY")
                throw new ArgumentException("Invalid PEM object type. Expected 'EC PUBLIC KEY'.");

            var curve = ECNamedCurveTable.GetByName(curveName.ToString());
            var domainParameters = new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H, curve.GetSeed());
            var q = curve.Curve.DecodePoint(pemObject.Content);
            return new ECPublicKeyParameters(q, domainParameters);
        }
    }

    /// <summary>
    /// Retrieves an ECDSA public key from a compressed Base64-encoded string using a specified curve.
    /// </summary>
    /// <param name="base64">A string containing the compressed Base64-encoded ECDSA public key.</param>
    /// <param name="curveName">The ECNamedCurve to be used for the retrieved key. Default is secp256k1.</param>
    /// <returns>An ECPublicKeyParameters instance representing the decoded ECDSA public key.</returns>
    /// <remarks>
    /// This method first converts the Base64-encoded string into a byte array.
    /// Then, it retrieves the specified named curve parameters and decodes the point from the byte array.
    /// Finally, it creates and returns an ECPublicKeyParameters instance using the decoded point and the domain parameters.
    /// </remarks>
    public static ECPublicKeyParameters GetCompressedECDSAPublicKeyFromBase64(this string base64, ECNamedCurve curveName = ECNamedCurve.secp256k1)
    {
        var publicKeyBytes = Convert.FromBase64String(base64);

        var curve = ECNamedCurveTable.GetByName(curveName.ToString());
        var domainParameters = new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H, curve.GetSeed());
        var decodePoint = curve.Curve.DecodePoint(publicKeyBytes);

        return new ECPublicKeyParameters(decodePoint, domainParameters);
    }
}