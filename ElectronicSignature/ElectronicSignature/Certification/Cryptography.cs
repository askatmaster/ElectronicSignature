using System.Collections;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;
using X509Certificate = Org.BouncyCastle.X509.X509Certificate;
namespace ElectronicSignature.Certification;

public static class Cryptography
{
    /// <summary>
    /// Generates an RSA key pair with the specified key size, or a default size of 2048 bits if none is provided.
    /// </summary >
    /// <param name="keySize" >The size of the RSA key pair to generate, in bits. Defaults to 2048 bits if not specified.</param >
    /// <returns >An AsymmetricCipherKeyPair containing the generated RSA public and private keys.</returns>
    /// <example>
    /// <code>
    /// //Generate a default 2048-bit RSA key pair
    /// AsymmetricCipherKeyPair rsaKeyPair = GenerateRSAKeyPair();
    /// //Generate a 4096-bit RSA key pair
    /// AsymmetricCipherKeyPair customRsaKeyPair = GenerateRSAKeyPair(4096);
    /// </code>
    /// </example>
    /// <remarks>
    /// The generated RSA key pair can be used for various cryptographic operations, such as signing, encryption, and decryption.
    /// Note that generating larger key sizes may take longer and consume more resources.
    /// </remarks>
    public static AsymmetricCipherKeyPair GenerateRSAKeyPair(int keySize = 2048)
    {
        var keyGenerationParameters = new KeyGenerationParameters(new SecureRandom(), keySize);
        var keyPairGenerator = new RsaKeyPairGenerator();
        keyPairGenerator.Init(keyGenerationParameters);

        return keyPairGenerator.GenerateKeyPair();
    }

    /// <summary>
    /// Generates an ECDSA key pair using the specified elliptic curve algorithm, or "secp256k1" by default if none is provided.
    /// </summary>
    /// <param name="algoritm">The name of the elliptic curve algorithm to use for key pair generation. Defaults to "secp256k1" if not specified.</param>
    /// <returns>An AsymmetricCipherKeyPair containing the generated ECDSA public and private keys.</returns>
    /// <example>
    /// <code>
    /// // Generate a secp256k1 ECDSA key pair (default)
    /// AsymmetricCipherKeyPair ecdsaKeyPair = GenerateECDSAKeyPair();
    /// // Generate a secp384r1 ECDSA key pair
    /// AsymmetricCipherKeyPair customEcdsaKeyPair = GenerateECDSAKeyPair(ECNamedCurve.secp384r1);
    /// </code>
    /// </example>
    /// <remarks>
    /// The generated ECDSA key pair can be used for various cryptographic operations, such as signing and verifying digital signatures.
    /// The key generation process is generally faster and the resulting keys are smaller compared to RSA for equivalent security.
    /// </remarks>
    public static AsymmetricCipherKeyPair GenerateECDSAKeyPair(ECNamedCurve algoritm = ECNamedCurve.secp256k1)
    {
        var curve = ECNamedCurveTable.GetByName(algoritm.ToString());
        var domainParameters = new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H, curve.GetSeed());
        var keyGenerationParameters = new ECKeyGenerationParameters(domainParameters, new SecureRandom());
        var generator = new ECKeyPairGenerator();
        generator.Init(keyGenerationParameters);

        return generator.GenerateKeyPair();
    }

    /// <summary>
    /// Determines if the given AsymmetricKeyParameter represents an RSA key.
    /// </summary>
    /// <param name="key">The AsymmetricKeyParameter to evaluate.</param>
    /// <returns>True if the key is an RSA key; otherwise, false.</returns>
    public static bool IsRSAKey(this AsymmetricKeyParameter key)
    {
        switch(key)
        {
            case RsaPrivateCrtKeyParameters:
            case RsaKeyParameters:
                return true;
            default:
                return false;
        }
    }

    /// <summary>
    /// Determines if the given AsymmetricKeyParameter represents an ECDSA key.
    /// </summary>
    /// <param name="key">The AsymmetricKeyParameter to evaluate.</param>
    /// <returns>True if the key is an ECDSA key; otherwise, false.</returns>
    public static bool IsECDSAKey(this AsymmetricKeyParameter key)
    {
        switch(key)
        {
            case ECPrivateKeyParameters:
            case ECPublicKeyParameters:
                return true;
            default:
                return false;
        }
    }

    /// <summary>
    /// Determines if the given X509Certificate2 contains an ECDSA public key.
    /// </summary>
    /// <param name="cert">The X509Certificate2 to evaluate.</param>
    /// <returns>True if the certificate contains an ECDSA public key; otherwise, false.</returns>
    /// <exception cref="Exception">Thrown when the public key type is unknown.</exception>
    public static bool IsECDSAKey(this X509Certificate2 cert)
    {
        // Determining the type of public key
        var keyAlgorithm = cert.PublicKey.Oid.FriendlyName;

        if (keyAlgorithm != null && keyAlgorithm.Contains("RSA"))
            return false;
        if (keyAlgorithm != null && (keyAlgorithm.Contains("ECDSA") || keyAlgorithm.Contains("ECDsa")))
            return true;

        throw new Exception("Unknown public key type");
    }

    /// <summary>
    /// Determines if the given X509Certificate2 contains an RSA public key.
    /// </summary>
    /// <param name="cert">The X509Certificate2 to evaluate.</param>
    /// <returns>True if the certificate contains an RSA public key; otherwise, false.</returns>
    /// <exception cref="Exception">Thrown when the public key type is unknown.</exception>
    public static bool IsRSAKey(this X509Certificate2 cert)
    {
        // Determining the type of public key
        var keyAlgorithm = cert.PublicKey.Oid.FriendlyName;

        if (keyAlgorithm != null && keyAlgorithm.Contains("RSA"))
            return true;
        if (keyAlgorithm != null && (keyAlgorithm.Contains("ECDSA") || keyAlgorithm.Contains("ECDsa")))
            return false;

        throw new Exception("Unknown public key type");
    }

    /// <summary>
    /// Generates a PKCS#10 Certificate Signing Request (CSR) with the specified subject information, cryptographic algorithm, and key pair.
    /// </summary>
    /// <param name="country">The country code (two-letter ISO 3166).</param>
    /// <param name="state">The state or province name.</param>
    /// <param name="locality">The locality or city name.</param>
    /// <param name="organization">The organization name.</param>
    /// <param name="organizationalUnit">The organizational unit name.</param>
    /// <param name="commonName">The common name (e.g., domain name or hostname).</param>
    /// <param name="algorithm">The cryptographic algorithm to be used (e.g., RSA or ECDSA).</param>
    /// <param name="keyPair">The asymmetric key pair to be associated with the CSR.</param>
    /// <returns>A Pkcs10CertificationRequest containing the generated CSR.</returns>
    /// <exception cref="Exception">Thrown when the key pair type is unknown.</exception>
    public static Pkcs10CertificationRequest GenerateCSR(string country,
                                                         string state,
                                                         string locality,
                                                         string organization,
                                                         string organizationalUnit,
                                                         string commonName,
                                                         CryptographyAlgorithm algorithm,
                                                         AsymmetricCipherKeyPair keyPair)
    {
        var subject = new X509Name($"C={country}, ST={state}, L={locality}, O={organization}, OU={organizationalUnit}, CN={commonName}");

        var algorithmName = algorithm.ToString();

        var isRSA = algorithmName.IsRsaAlgorithm();

        var csr = keyPair.Private switch
        {
            ECPrivateKeyParameters when !isRSA => new Pkcs10CertificationRequest(algorithmName, subject, keyPair.Public, null, keyPair.Private),
            RsaPrivateCrtKeyParameters when isRSA => new Pkcs10CertificationRequest(algorithmName, subject, keyPair.Public, null, keyPair.Private),
            _ => throw new Exception("Unknown key pair type")
        };

        return csr;
    }

    /// <summary>
    /// Generates a self-signed X509Certificate using the provided PKCS#10 Certificate Signing Request (CSR), private key, and validity period.
    /// </summary>
    /// <param name="csr">The Pkcs10CertificationRequest used as a base for the self-signed certificate.</param>
    /// <param name="privateKey">The AsymmetricKeyParameter representing the private key to sign the certificate with.</param>
    /// <param name="startDate">The start date for the certificate's validity period.</param>
    /// <param name="endDate">The end date for the certificate's validity period.</param>
    /// <param name="algorithm">The cryptographic algorithm to be used for signing the certificate. Defaults to CryptographyAlgorithm.SHA256withRSA.</param>
    /// <returns>A self-signed X509Certificate.</returns>
    public static X509Certificate GenerateSelfSignedCert(Pkcs10CertificationRequest csr,
                                                         AsymmetricKeyParameter privateKey,
                                                         DateTime startDate,
                                                         DateTime endDate,
                                                         CryptographyAlgorithm algorithm = CryptographyAlgorithm.SHA256withRSA)
    {
        // Create a CSR-based self-signed certificate
        var csrInfo = csr.GetCertificationRequestInfo();
        var certGenerator = new X509V3CertificateGenerator();
        var randomGenerator = new CryptoApiRandomGenerator();
        var random = new SecureRandom(randomGenerator);
        var serialNumber = BigIntegers.CreateRandomInRange(BigInteger.One, BigInteger.ValueOf(long.MaxValue), random);

        certGenerator.SetSerialNumber(serialNumber);
        certGenerator.SetIssuerDN(csrInfo.Subject);
        certGenerator.SetNotBefore(startDate);
        certGenerator.SetNotAfter(endDate);
        certGenerator.SetSubjectDN(csrInfo.Subject);
        certGenerator.SetPublicKey(csr.GetPublicKey());

        // Add the BasicConstraints and SubjectKeyIdentifier extensions
        certGenerator.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false));
        certGenerator.AddExtension(X509Extensions.SubjectKeyIdentifier, false, new SubjectKeyIdentifierStructure(csr.GetPublicKey()));

        // Create a signature factory for the specified algorithm and private key
        ISignatureFactory signatureFactory = new Asn1SignatureFactory(algorithm.ToString(), privateKey);

        // Sign the certificate with the specified signature algorithm
        return certGenerator.Generate(signatureFactory);
    }

    /// <summary>
    /// Generates a signed X509Certificate using the provided PKCS#10 Certificate Signing Request (CSR), signer certificate, and validity period.
    /// </summary>
    /// <param name="csr">The Pkcs10CertificationRequest used as a base for the signed certificate.</param>
    /// <param name="pfx">The X509Certificate2 representing the signer's certificate, including its private key.</param>
    /// <param name="pfxPassword">The optional password for the signer's PFX file, if required.</param>
    /// <param name="startDate">The start date for the certificate's validity period.</param>
    /// <param name="endDate">The end date for the certificate's validity period.</param>
    /// <param name="algorithm">The cryptographic algorithm to be used for signing the certificate. Defaults to CryptographyAlgorithm.SHA256withRSA.</param>
    /// <returns>A signed X509Certificate.</returns>
    public static X509Certificate GenerateSignedCertificate(Pkcs10CertificationRequest csr,
                                                            X509Certificate2 pfx,
                                                            string? pfxPassword,
                                                            DateTime startDate,
                                                            DateTime endDate,
                                                            CryptographyAlgorithm algorithm = CryptographyAlgorithm.SHA256withRSA)
    {
        // Загрузка PFX-файла
        AsymmetricKeyParameter pfxPrivateKey;

        try
        {
            pfxPrivateKey = DotNetUtilities.GetKeyPair(pfx.GetRSAPrivateKey()).Private ?? DotNetUtilities.GetKeyPair(pfx.GetECDsaPrivateKey()).Private;
        }
        catch (Exception)
        {
            pfxPrivateKey = pfx.LoadPrivateKeyFromCert(pfxPassword);
        }

        var pfxBouncyCastleCertificate = DotNetUtilities.FromX509Certificate(pfx);

        // Создание сертификата на основе CSR
        var csrInfo = csr.GetCertificationRequestInfo();
        var certGenerator = new X509V3CertificateGenerator();

        var randomGenerator = new CryptoApiRandomGenerator();
        var random = new SecureRandom(randomGenerator);
        var serialNumber = BigIntegers.CreateRandomInRange(BigInteger.One, BigInteger.ValueOf(long.MaxValue), random);

        certGenerator.SetSerialNumber(serialNumber);
        certGenerator.SetIssuerDN(pfxBouncyCastleCertificate.SubjectDN);
        certGenerator.SetNotBefore(startDate);
        certGenerator.SetNotAfter(endDate);
        certGenerator.SetSubjectDN(csrInfo.Subject);
        certGenerator.SetPublicKey(csr.GetPublicKey());

        // Добавление расширений
        certGenerator.AddExtension(X509Extensions.BasicConstraints.Id, false, new BasicConstraints(false));
        certGenerator.AddExtension(X509Extensions.SubjectKeyIdentifier.Id, false, new SubjectKeyIdentifierStructure(csr.GetPublicKey()));

        // Создание подписи и генерация сертификата
        ISignatureFactory signatureFactory = new Asn1SignatureFactory(algorithm.ToString(), pfxPrivateKey);

        return certGenerator.Generate(signatureFactory);
    }

    /// <summary>
    /// Decrypts the given data using the private certificate provided as a byte array.
    /// </summary>
    /// <param name="encryptedData">The encrypted data to be decrypted as a byte array.</param>
    /// <param name="privateCert">The private certificate as a byte array.</param>
    /// <param name="password">The optional password for the private certificate, if required.</param>
    /// <returns>The decrypted data as a byte array.</returns>
    public static byte[] DecryptDataWithPrivateCert(byte[] encryptedData, byte[] privateCert, string? password)
    {
        return DecryptDataWithPrivateCert(encryptedData, privateCert.GetPrivateCert(password), password);
    }

    /// <summary>
    /// Decrypts the given data using the private certificate provided as a file path.
    /// </summary>
    /// <param name="encryptedData">The encrypted data to be decrypted as a byte array.</param>
    /// <param name="privateCertPath">The file path to the private certificate.</param>
    /// <param name="password">The optional password for the private certificate, if required.</param>
    /// <returns>The decrypted data as a byte array.</returns>
    public static byte[] DecryptDataWithPrivateCert(byte[] encryptedData, string privateCertPath, string? password)
    {
        return DecryptDataWithPrivateCert(encryptedData, privateCertPath.GetPrivateCert(password), password);
    }

    /// <summary>
    /// Decrypts the given Base64-encoded data using the private certificate provided as a byte array.
    /// </summary>
    /// <param name="base64Data">The encrypted data to be decrypted as a Base64-encoded string.</param>
    /// <param name="privateCert">The private certificate as a byte array.</param>
    /// <param name="password">The optional password for the private certificate, if required.</param>
    /// <returns>The decrypted data as a byte array.</returns>
    public static byte[] DecryptDataWithPrivateCert(string base64Data, byte[] privateCert, string? password)
    {
        return DecryptDataWithPrivateCert(Convert.FromBase64String(base64Data), privateCert.GetPrivateCert(password), password);
    }

    /// <summary>
    /// Decrypts the given Base64-encoded data using the private certificate provided as a file path.
    /// </summary>
    /// <param name="base64Data">The encrypted data to be decrypted as a Base64-encoded string.</param>
    /// <param name="privateCertPath">The file path to the private certificate.</param>
    /// <param name="password">The optional password for the private certificate, if required.</param>
    /// <returns>The decrypted data as a byte array.</returns>
    public static byte[] DecryptDataWithPrivateCert(string base64Data, string privateCertPath, string? password)
    {
        return DecryptDataWithPrivateCert(Convert.FromBase64String(base64Data), privateCertPath.GetPrivateCert(password), password);
    }

    /// <summary>
    /// Decrypts the given Base64-encoded data using the provided X509Certificate2 containing the private key.
    /// </summary>
    /// <param name="base64Data">The encrypted data to be decrypted as a Base64-encoded string.</param>
    /// <param name="privateCert">The X509Certificate2 containing the private key.</param>
    /// <param name="password">The optional password for the private certificate, if required.</param>
    /// <returns>The decrypted data as a byte array.</returns>
    public static byte[] DecryptDataWithPrivateCert(string base64Data, X509Certificate2 privateCert, string ? password)
    {
        return DecryptDataWithPrivateCert(Convert.FromBase64String(base64Data), privateCert, password);
    }

    /// <summary>
    /// Decrypts the given data using the provided X509Certificate2 containing the private key.
    /// </summary>
    /// <param name="encryptedData">The encrypted data to be decrypted as a byte array.</param>
    /// <param name="privateCert">The X509Certificate2 containing the private key.</param>
    /// <param name="password">The optional password for the private certificate, if required.</param>
    /// <returns>The decrypted data as a byte array.</returns>
    public static byte[] DecryptDataWithPrivateCert(byte[] encryptedData, X509Certificate2 privateCert, string ? password)
    {
        AsymmetricKeyParameter key;

        try
        {
            key = DotNetUtilities.GetKeyPair(privateCert.GetRSAPrivateKey()).Private ?? DotNetUtilities.GetKeyPair(privateCert.GetECDsaPrivateKey()).Private;
        }
        catch (Exception)
        {
            key = privateCert.LoadPrivateKeyFromCert(password);
        }

        var x509Certificate = DotNetUtilities.FromX509Certificate(privateCert);

        var recipientInfos = new CmsEnvelopedData(encryptedData).GetRecipientInfos();

        RecipientInformation? firstRecipient = null;
        foreach (var recipientInfo in recipientInfos.GetRecipients())
        {
            if(recipientInfo.RecipientID.Issuer.Equivalent(x509Certificate.IssuerDN) || recipientInfo.RecipientID.SerialNumber.Equals(x509Certificate.SerialNumber))
                firstRecipient = recipientInfo;
        }

        return firstRecipient!.GetContent(key);
    }

    /// <summary>
    /// Encrypts the given data using the public certificate provided as a byte array.
    /// </summary>
    /// <param name="data">The data to be encrypted as a byte array.</param>
    /// <param name="publicCert">The public certificate as a byte array.</param>
    /// <returns>The encrypted data as a byte array.</returns>
    public static byte[] EncryptDataByPublicCert(byte[] data, byte[] publicCert)
    {
        return EncryptDataByPublicCert(data, publicCert.GetPublicCert());
    }

    /// <summary>
    /// Encrypts the given data using the public certificate provided as a file path.
    /// </summary>
    /// <param name="data">The data to be encrypted as a byte array.</param>
    /// <param name="publicCertPath">The file path to the public certificate.</param>
    /// <returns>The encrypted data as a byte array.</returns>
    public static byte[] EncryptDataByPublicCert(byte[] data, string publicCertPath)
    {
        return EncryptDataByPublicCert(data, publicCertPath.GetPublicCert());
    }

    /// <summary>
    /// Encrypts the given string data using the provided X509Certificate2 containing the public key.
    /// </summary>
    /// <param name="data">The data to be encrypted as a string.</param>
    /// <param name="publicCert">The X509Certificate2 containing the public key.</param>
    /// <returns>The encrypted data as a byte array.</returns>
    public static byte[] EncryptDataByPublicCert(string data, X509Certificate2 publicCert)
    {
        return EncryptDataByPublicCert(Encoding.UTF8.GetBytes(data), publicCert);
    }

    /// <summary>
    /// Encrypts the given data using the provided X509Certificate2 containing the public key.
    /// </summary>
    /// <param name="data">The data to be encrypted as a byte array.</param>
    /// <param name="publicCert">The X509Certificate2 containing the public key.</param>
    /// <returns>The encrypted data as a byte array.</returns>
    public static byte[] EncryptDataByPublicCert(byte[] data, X509Certificate2 publicCert)
    {
        var envelopGenerator = new CmsEnvelopedDataGenerator();
        var cert = new X509CertificateParser().ReadCertificate(publicCert.RawData);
        envelopGenerator.AddKeyTransRecipient(cert);

        return envelopGenerator.Generate(new CmsProcessableByteArray(data), CmsEnvelopedGenerator.DesEde3Cbc).GetEncoded();
    }

    /// <summary>
    /// Extracts the signed data from the provided Base64 encoded signed data.
    /// </summary>
    /// <param name="base64SigendData">The Base64 encoded signed data.</param>
    /// <returns>The extracted signed data as a byte array.</returns>
    public static byte[] ExtractSignedData(string base64SigendData)
    {
        var sigendData = Convert.FromBase64String(base64SigendData);

        return ExtractSignedData(sigendData);
    }

    /// <summary>
    /// Extracts the signed data from the provided byte array of signed data.
    /// </summary>
    /// <param name="sigendData">The signed data as a byte array.</param>
    /// <returns>The extracted signed data as a byte array.</returns>
    /// <exception cref="ArgumentNullException">Thrown when the provided signed data is null.</exception>
    /// <exception cref="InvalidOperationException">Thrown when attempting to extract enveloped content from a detached signed data.</exception>
    public static byte[] ExtractSignedData(byte[] sigendData)
    {
        if (sigendData == null)
            throw new ArgumentNullException(nameof(sigendData));

        var signedCm = new SignedCms();
        signedCm.Decode(sigendData);

        if (signedCm.Detached)
            throw new InvalidOperationException("Cannot extract enveloped content from a detached sigendData.");

        return signedCm.ContentInfo.Content;
    }

    /// <summary>
    /// Signs the given data using the provided byte array of the private certificate.
    /// </summary>
    /// <param name="data">The data to be signed as a byte array.</param>
    /// <param name="privateCert">The byte array of the private certificate.</param>
    /// <param name="password">The password for the private certificate, if applicable.</param>
    /// <returns>The signed data as a byte array.</returns>
    public static byte[] SignDataByPrivateCert(byte[] data, byte[] privateCert, string? password)
    {
        return SignDataByPrivateCert(data, privateCert.GetPrivateCert( password));
    }

    /// <summary>
    /// Signs the given data using the provided private certificate file path.
    /// </summary>
    /// <param name="data">The data to be signed as a byte array.</param>
    /// <param name="privateCertPath">The file path of the private certificate.</param>
    /// <param name="password">The password for the private certificate, if applicable.</param>
    /// <returns>The signed data as a byte array.</returns>
    public static byte[] SignDataByPrivateCert(byte[] data, string privateCertPath, string? password)
    {
        return SignDataByPrivateCert(data, privateCertPath.GetPrivateCert(password));
    }

    /// <summary>
    /// Signs the given Base64 encoded data using the provided byte array of the private certificate.
    /// </summary>
    /// <param name="base64Data">The Base64 encoded data to be signed.</param>
    /// <param name="privateCert">The byte array of the private certificate.</param>
    /// <param name="password">The password for the private certificate, if applicable.</param>
    /// <returns>The signed data as a byte array.</returns>
    public static byte[] SignDataByPrivateCert(string base64Data, byte[] privateCert, string? password)
    {
        return SignDataByPrivateCert(Encoding.UTF8.GetBytes(base64Data), privateCert.GetPrivateCert(password));
    }

    /// <summary>
    /// Signs the given Base64 encoded data using the provided private certificate file path.
    /// </summary>
    /// <param name="base64Data">The Base64 encoded data to be signed.</param>
    /// <param name="privateCertPath">The file path of the private certificate.</param>
    /// <param name="password">The password for the private certificate, if applicable.</param>
    /// <returns>The signed data as a byte array.</returns>
    public static byte[] SignDataByPrivateCert(string base64Data, string privateCertPath, string? password)
    {
        return SignDataByPrivateCert(Encoding.UTF8.GetBytes(base64Data), privateCertPath.GetPrivateCert(password));
    }

    /// <summary>
    /// Signs the given Base64 encoded data using the provided X509Certificate2 containing the private key.
    /// </summary>
    /// <param name="base64Data">The Base64 encoded data to be signed.</param>
    /// <param name="privateKeyCert">The X509Certificate2 containing the private key.</param>
    /// <returns>The signed data as a byte array.</returns>
    public static byte[] SignDataByPrivateCert(string base64Data, X509Certificate2 privateKeyCert)
    {
        return SignDataByPrivateCert(Encoding.UTF8.GetBytes(base64Data), privateKeyCert);
    }

    /// <summary>
    /// Signs the given data using the provided X509Certificate2 containing the private key.
    /// </summary>
    /// <param name="data">The data to be signed as a byte array.</param>
    /// <param name="privateKeyCert">The X509Certificate2 containing the private key.</param>
    /// <returns>The signed data as a byte array.</returns>
    public static byte[] SignDataByPrivateCert(byte[] data, X509Certificate2 privateKeyCert)
    {
        if (data == null)
            throw new ArgumentNullException(nameof(data));

        if (privateKeyCert == null)
            throw new ArgumentNullException(nameof(privateKeyCert));

        var signedCms = new SignedCms(new ContentInfo(data));
        signedCms.ComputeSignature(new CmsSigner(SubjectIdentifierType.IssuerAndSerialNumber, privateKeyCert));

        return signedCms.Encode();
    }

    /// <summary>
    /// Signs the given data using the provided private key.
    /// </summary>
    /// <param name="data">The data to be signed as a byte array.</param>
    /// <param name="privateCert">The private certificate as a byte array.</param>
    /// <param name="password">The optional password for the private certificate.</param>
    /// <returns>The signed data as a byte array.</returns>
    public static byte[] SignDataByPrivateKey(byte[] data, byte[] privateCert, string? password)
    {
        return SignDataByPrivateKey(data, privateCert.LoadPrivateKeyFromCert(password));
    }

    /// <summary>
    /// Signs the given data using the private key from the provided certificate file path.
    /// </summary>
    /// <param name="data">The data to be signed as a byte array.</param>
    /// <param name="privateCertPath">The file path to the private certificate.</param>
    /// <param name="password">The optional password for the private certificate.</param>
    /// <returns>The signed data as a byte array.</returns>
    public static byte[] SignDataByPrivateKey(byte[] data, string privateCertPath, string? password)
    {
        return SignDataByPrivateKey(data, privateCertPath.LoadPrivateKeyFromCert(password));
    }

    /// <summary>
    /// Signs the given data using the provided private key.
    /// </summary>
    /// <param name="data">The data to be signed as a string.</param>
    /// <param name="privateCert">The private certificate as a byte array.</param>
    /// <param name="password">The optional password for the private certificate.</param>
    /// <returns>The signed data as a byte array.</returns>
    public static byte[] SignDataByPrivateKey(string data, byte[] privateCert, string? password)
    {
        return SignDataByPrivateKey(Encoding.UTF8.GetBytes(data), privateCert.LoadPrivateKeyFromCert(password));
    }

    /// <summary>
    /// Signs the given data using the private key from the provided certificate file path.
    /// </summary>
    /// <param name="data">The data to be signed as a string.</param>
    /// <param name="privateCertPath">The file path to the private certificate.</param>
    /// <param name="password">The optional password for the private certificate.</param>
    /// <returns>The signed data as a byte array.</returns>
    public static byte[] SignDataByPrivateKey(string data, string privateCertPath, string? password)
    {
        return SignDataByPrivateKey(Encoding.UTF8.GetBytes(data), privateCertPath.LoadPrivateKeyFromCert(password));
    }

    /// <summary>
    /// Signs the given data using the private key from the provided PEM file path.
    /// </summary>
    /// <param name="data">The data to be signed as a string.</param>
    /// <param name="privateKeyPath">The file path to the PEM file containing the private key.</param>
    /// <returns>The signed data as a byte array.</returns>
    public static byte[] SignDataByPrivateKey(string data, string privateKeyPath)
    {
        return SignDataByPrivateKey(Encoding.UTF8.GetBytes(data), privateKeyPath.GetKeyPairFromPem().Private);
    }

    /// <summary>
    /// Signs the given data using the private key from the provided PEM file path.
    /// </summary>
    /// <param name="data">The data to be signed as a byte array.</param>
    /// <param name="privateKeyPath">The file path to the PEM file containing the private key.</param>
    /// <returns>The signed data as a byte array.</returns>
    public static byte[] SignDataByPrivateKey(byte[] data, string privateKeyPath)
    {
        return SignDataByPrivateKey(data, privateKeyPath.GetKeyPairFromPem().Private);
    }

    /// <summary>
    /// Signs the given data using the provided AsymmetricKeyParameter private key.
    /// </summary>
    /// <param name="data">The data to be signed as a string.</param>
    /// <param name="privateKey">The private key as an AsymmetricKeyParameter object.</param>
    /// <returns>The signed data as a byte array.</returns>
    public static byte[] SignDataByPrivateKey(string data, AsymmetricKeyParameter privateKey)
    {
        return SignDataByPrivateKey(Encoding.UTF8.GetBytes(data), privateKey);
    }

    /// <summary>
    /// Signs the given data using the provided AsymmetricKeyParameter private key.
    /// </summary>
    /// <param name="data">The data to be signed as a byte array.</param>
    /// <param name="privateKey">The private key as an AsymmetricKeyParameter object.</param>
    /// <param name="algorithm">Algorithm for sign.</param>
    /// <returns>The signed data as a byte array.</returns>
    public static byte[] SignDataByPrivateKey(byte[] data, AsymmetricKeyParameter privateKey, CryptographyAlgorithm algorithm = CryptographyAlgorithm.SHA256withRSA)
    {
        var signer = SignerUtilities.GetSigner(algorithm.ToString());
        signer.Init(true, privateKey);

        signer.BlockUpdate(data, 0, data.Length);

        return signer.GenerateSignature();
    }

    /// <summary>
    /// Verifies signed data using the same certificate and extracts the decoded message.
    /// </summary>
    /// <param name="sigendData">The signed data as a byte array.</param>
    /// <param name="publicCert">The public certificate as an X509Certificate2 object.</param>
    /// <param name="decodedMessage">The decoded message as an output byte array.</param>
    /// <returns>True if the signed data is verified, otherwise false.</returns>
    public static bool VerifySignedDataBySameCert(byte[] sigendData, X509Certificate2 publicCert, out byte[]? decodedMessage)
    {
        bool isValid;
        decodedMessage = null;

        if (sigendData == null)
            throw new ArgumentNullException(nameof(sigendData));

        if (publicCert == null)
            throw new ArgumentNullException(nameof(publicCert));

        var signedCms = new SignedCms();

        signedCms.Decode(sigendData);
        signedCms.CheckSignature(new X509Certificate2Collection(publicCert), false);
        decodedMessage = signedCms.ContentInfo.Content;

        // We check that the signature is made with the certificate that we expected
        var signer = signedCms.SignerInfos[0];
        var signingCert = signer.Certificate;

        if(signingCert is null)
            throw new Exception("Not found certificate from sigendData");

        if (signingCert.Thumbprint == publicCert.Thumbprint)
        {
            isValid = true;
        }
        else
        {
            isValid = false;
            Console.WriteLine("The message was signed by a different certificate.");
        }

        return isValid;
    }

    /// <summary>
    /// Verifies signed data using the root certificate, ensuring trust communication, and extracts the decoded message.
    /// </summary>
    /// <param name="sigendData">The signed data as a byte array.</param>
    /// <param name="publicCert">The public certificate as an X509Certificate2 object.</param>
    /// <param name="decodedMessage">The decoded message as an output byte array.</param>
    /// <returns>True if the signed data is verified, otherwise false.</returns>
    public static bool VerifySignedDataRootCertAndTrustCommunication(byte[] sigendData, X509Certificate2 publicCert, out byte[]? decodedMessage)
    {
        bool flag;
        decodedMessage = null;

        if (sigendData == null)
            throw new ArgumentNullException(nameof(sigendData));

        if (publicCert == null)
            throw new ArgumentNullException(nameof(publicCert));

        var signedCm = new SignedCms();

        try
        {
            signedCm.Decode(sigendData);
            signedCm.CheckSignature(new X509Certificate2Collection(publicCert), false);
            decodedMessage = signedCm.ContentInfo.Content;
            flag = true;
        }
        catch (CryptographicException)
        {
            flag = false;
        }

        return flag;
    }

    /// <summary>
    /// Verifies signed data using the certificate issuer and extracts the decoded message.
    /// </summary>
    /// <param name="signature">The signed data as a byte array.</param>
    /// <param name="publicCert">The public certificate as an X509Certificate2 object.</param>
    /// <param name="decodedMessage">The decoded message as an output byte array.</param>
    /// <returns>True if the signed data is verified, otherwise false.</returns>
    public static bool VerifySignedDataByCertIssuer(byte[] signature, X509Certificate2 publicCert, out byte[]? decodedMessage)
    {
        bool isValid;
        decodedMessage = null;

        if (signature == null)
            throw new ArgumentNullException(nameof(signature));

        if (publicCert == null)
            throw new ArgumentNullException(nameof(publicCert));

        var signedCms = new SignedCms();

        try
        {
            signedCms.Decode(signature);
            signedCms.CheckSignature(new X509Certificate2Collection(publicCert), false);
            decodedMessage = signedCms.ContentInfo.Content;

            // We check that the signature is made with the certificate that we expected
            var signer = signedCms.SignerInfos[0];
            var signingCert = signer.Certificate;

            if(signingCert is null)
                throw new Exception("Not found certificate from sigendData");

            if (signingCert.Subject == publicCert.Issuer && signingCert.Issuer == publicCert.Issuer)
            {
                isValid = true;
            }
            else
            {
                isValid = false;
                Console.WriteLine("The message was signed by a different certificate.");
            }
        }
        catch (CryptographicException)
        {
            isValid = false;
        }

        return isValid;
    }

    /// <summary>
    /// Verifies signed data using a public key and a specified cryptographic algorithm.
    /// </summary>
    /// <param name="message">The original message as a string.</param>
    /// <param name="sigendData">The signed data as a byte array.</param>
    /// <param name="publicKey">The public key as an AsymmetricKeyParameter object.</param>
    /// <param name="algorithm">The cryptographic algorithm used for signing, default is SHA256withRSA.</param>
    /// <returns>True if the signed data is verified, otherwise false.</returns>
    public static bool VerifySignedByPublicKey(string message,
                                        byte[] sigendData,
                                        AsymmetricKeyParameter publicKey,
                                        CryptographyAlgorithm algorithm = CryptographyAlgorithm.SHA256withRSA)
    {
        var verifier = SignerUtilities.GetSigner(algorithm.ToString());
        verifier.Init(false, publicKey);

        var messageBytes = Encoding.UTF8.GetBytes(message);
        verifier.BlockUpdate(messageBytes, 0, messageBytes.Length);

        return verifier.VerifySignature(sigendData);
    }

    /// <summary>
    /// Verifies if the public key in <paramref name="certificate1"/> matches the private key in <paramref name="certificate2"/>.
    /// </summary>
    /// <param name="certificate1">The X.509 certificate containing the public key.</param>
    /// <param name="certificate2">The X.509 certificate containing the private key.</param>
    /// <returns>True if the public key in <paramref name="certificate1"/> matches the private key in <paramref name="certificate2"/>, otherwise false.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="certificate1"/> or <paramref name="certificate2"/> is null.</exception>
    /// <exception cref="Exception">Thrown when the public key algorithm of <paramref name="certificate1"/> or <paramref name="certificate2"/> is not supported.</exception>
    public static bool VerifyMatchBetweenPublicAndPrivateKeys(X509Certificate2 certificate1, X509Certificate2 certificate2)
    {
        // Retrieving public keys from certificates
        if(certificate1.IsRSAKey())
        {
            var key1 = certificate1.GetRSAPublicKey();
            var key2 = certificate2.GetRSAPublicKey();

            if(key1 is null)
                throw new Exception("Certificate1 Cryptography public key could not be retrieved");

            if(key2 is null)
                throw new Exception("Certificate2 Cryptography public key could not be retrieved");

            // Comparison of modules and exhibitors
            var params1 = key1.ExportParameters(false);
            var params2 = key2.ExportParameters(false);

            return StructuralComparisons.StructuralEqualityComparer.Equals(params1.Modulus, params2.Modulus)
             && StructuralComparisons.StructuralEqualityComparer.Equals(params1.Exponent, params2.Exponent);
        }

        if(certificate1.IsECDSAKey())
        {
            var key1 = certificate1.GetECDsaPublicKey();
            var key2 = certificate2.GetECDsaPublicKey();

            if(key1 is null)
                throw new Exception("Certificate1 Cryptography public key could not be retrieved");

            if(key2 is null)
                throw new Exception("Certificate2 Cryptography public key could not be retrieved");

            var params1 = key1.ExportParameters(false);
            var params2 = key2.ExportParameters(false);

            return StructuralComparisons.StructuralEqualityComparer.Equals(params1.Q, params2.Q)
             && StructuralComparisons.StructuralEqualityComparer.Equals(params1.D, params2.D);
        }

        throw new Exception("In this version of the library, only RSA and ECDSA keys are supported");
    }

    /// <summary>
    /// Encrypts a plaintext string using an RSA public key.
    /// </summary>
    /// <param name="plaintext">The plaintext string to encrypt.</param>
    /// <param name="publicKey">The RSA public key to use for encryption.</param>
    /// <returns>The Base64-encoded ciphertext.</returns>
    /// <remarks>
    /// This method uses the RSA encryption algorithm to encrypt the plaintext string using the provided public key.
    /// It first creates a new Pkcs1Encoding object with an RsaEngine, initializes it for encryption with the provided public key,
    /// converts the plaintext string to a byte array, and then passes it to the ProcessBlock method of the Pkcs1Encoding object.
    /// The resulting byte array is then Base64-encoded and returned as a string.
    /// </remarks>
    public static string EncryptDataWithPulicKey(string plaintext, AsymmetricKeyParameter publicKey)
    {
        var encryptEngine = new Pkcs1Encoding(new RsaEngine());
        encryptEngine.Init(true, publicKey);
        var plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
        var encryptedBytes = encryptEngine.ProcessBlock(plaintextBytes, 0, plaintextBytes.Length);

        return Convert.ToBase64String(encryptedBytes);
    }

    /// <summary>
    /// Decrypts a ciphertext string using an RSA private key.
    /// </summary>
    /// <param name="ciphertext">The Base64-encoded ciphertext to decrypt.</param>
    /// <param name="privateKey">The RSA private key to use for decryption.</param>
    /// <returns>The decrypted plaintext string.</returns>
    /// <remarks>
    /// This method uses the RSA decryption algorithm to decrypt the Base64-encoded ciphertext using the provided private key.
    /// It first creates a new Pkcs1Encoding object with an RsaEngine, initializes it for decryption with the provided private key,
    /// converts the Base64-encoded ciphertext string to a byte array, and then passes it to the ProcessBlock method of the Pkcs1Encoding object.
    /// The resulting byte array is then converted to a UTF-8 encoded plaintext string and returned.
    /// </remarks>
    public static string DecryptDataWithPrivateKey(string ciphertext, AsymmetricKeyParameter privateKey)
    {
        var decryptEngine = new Pkcs1Encoding(new RsaEngine());
        decryptEngine.Init(false, privateKey);
        var ciphertextBytes = Convert.FromBase64String(ciphertext);
        var decryptedBytes = decryptEngine.ProcessBlock(ciphertextBytes, 0, ciphertextBytes.Length);

        return Encoding.UTF8.GetString(decryptedBytes);
    }
}