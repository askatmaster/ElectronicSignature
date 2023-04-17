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
    public static AsymmetricCipherKeyPair GenerateRSAKeyPair(int keySize = 2048)
    {
        var keyGenerationParameters = new KeyGenerationParameters(new SecureRandom(), keySize);
        var keyPairGenerator = new RsaKeyPairGenerator();
        keyPairGenerator.Init(keyGenerationParameters);

        return keyPairGenerator.GenerateKeyPair();
    }

    public static AsymmetricCipherKeyPair GenerateECDSAKeyPair(string algoritm = "secp256k1")
    {
        var curve = ECNamedCurveTable.GetByName(algoritm);
        var domainParameters = new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H, curve.GetSeed());
        var keyGenerationParameters = new ECKeyGenerationParameters(domainParameters, new SecureRandom());
        var generator = new ECKeyPairGenerator();
        generator.Init(keyGenerationParameters);

        return generator.GenerateKeyPair();
    }

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

    public static bool IsECDSAKey(this X509Certificate2 cert)
    {
        // Получение публичного ключа из сертификата
        var publicKey = cert.PublicKey;

        // Определение типа публичного ключа
        var keyAlgorithm = publicKey.Oid.FriendlyName;

        if (keyAlgorithm != null && keyAlgorithm.Contains("RSA"))
            return false;
        if (keyAlgorithm != null && (keyAlgorithm.Contains("ECDSA") || keyAlgorithm.Contains("ECDsa")))
            return true;

        throw new Exception("Unknown public key type");
    }

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

    public static X509Certificate GenerateSelfSignedCert(Pkcs10CertificationRequest csr,
                                                         AsymmetricKeyParameter privateKey,
                                                         DateTime startDate,
                                                         DateTime endDate,
                                                         CryptographyAlgorithm algorithm = CryptographyAlgorithm.SHA256withRSA)
    {
        // Создание самоподписанного сертификата на основе CSR
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

    public static byte[] DecryptDataWithPrivateCert(byte[] encryptedData, byte[] privateCert, string? password)
    {
        return DecryptDataWithPrivateCert(encryptedData, privateCert.GetPrivateCert(password), password);
    }

    public static byte[] DecryptDataWithPrivateCert(byte[] encryptedData, string privateCertPath, string? password)
    {
        return DecryptDataWithPrivateCert(encryptedData, privateCertPath.GetPrivateCert(password), password);
    }

    public static byte[] DecryptDataWithPrivateCert(string base64Data, byte[] privateCert, string? password)
    {
        return DecryptDataWithPrivateCert(Convert.FromBase64String(base64Data), privateCert.GetPrivateCert(password), password);
    }

    public static byte[] DecryptDataWithPrivateCert(string base64Data, string privateCertPath, string? password)
    {
        return DecryptDataWithPrivateCert(Convert.FromBase64String(base64Data), privateCertPath.GetPrivateCert(password), password);
    }

    public static byte[] DecryptDataWithPrivateCert(string base64Data, X509Certificate2 privateCert, string ? password)
    {
        return DecryptDataWithPrivateCert(Convert.FromBase64String(base64Data), privateCert, password);
    }

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

    public static byte[] EncryptDataByPublicCert(byte[] data, byte[] publicCert)
    {
        return EncryptDataByPublicCert(data, publicCert.GetPublicCert());
    }

    public static byte[] EncryptDataByPublicCert(byte[] data, string publicCertPath)
    {
        return EncryptDataByPublicCert(data, publicCertPath.GetPublicCert());
    }

    public static byte[] EncryptDataByPublicCert(string data, X509Certificate2 publicCert)
    {
        return EncryptDataByPublicCert(Encoding.UTF8.GetBytes(data), publicCert);
    }

    public static byte[] EncryptDataByPublicCert(byte[] data, X509Certificate2 publicCert)
    {
        var envelopGenerator = new CmsEnvelopedDataGenerator();
        var cert = new X509CertificateParser().ReadCertificate(publicCert.RawData);
        envelopGenerator.AddKeyTransRecipient(cert);

        return envelopGenerator.Generate(new CmsProcessableByteArray(data), CmsEnvelopedGenerator.DesEde3Cbc).GetEncoded();
    }

    public static byte[] ExtractSignedData(string base64SigendData)
    {
        var sigendData = Convert.FromBase64String(base64SigendData);

        return ExtractSignedData(sigendData);
    }

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

    public static byte[] SignDataByPrivateCert(byte[] data, byte[] privateCert, string? password)
    {
        return SignDataByPrivateCert(data, privateCert.GetPrivateCert( password));
    }

    public static byte[] SignDataByPrivateCert(byte[] data, string privateCertPath, string? password)
    {
        return SignDataByPrivateCert(data, privateCertPath.GetPrivateCert(password));
    }

    public static byte[] SignDataByPrivateCert(string base64Data, byte[] privateCert, string? password)
    {
        return SignDataByPrivateCert(Encoding.UTF8.GetBytes(base64Data), privateCert.GetPrivateCert(password));
    }

    public static byte[] SignDataByPrivateCert(string base64Data, string privateCertPath, string? password)
    {
        return SignDataByPrivateCert(Encoding.UTF8.GetBytes(base64Data), privateCertPath.GetPrivateCert(password));
    }

    public static byte[] SignDataByPrivateCert(string base64Data, X509Certificate2 privateKeyCert)
    {
        return SignDataByPrivateCert(Encoding.UTF8.GetBytes(base64Data), privateKeyCert);
    }

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

    public static byte[] SignDataByPrivateKey(byte[] data, byte[] privateCert, string? password)
    {
        return SignDataByPrivateKey(data, privateCert.LoadPrivateKeyFromCert(password));
    }

    public static byte[] SignDataByPrivateKey(byte[] data, string privateCertPath, string? password)
    {
        return SignDataByPrivateKey(data, privateCertPath.LoadPrivateKeyFromCert(password));
    }

    public static byte[] SignDataByPrivateKey(string data, byte[] privateCert, string? password)
    {
        return SignDataByPrivateKey(Encoding.UTF8.GetBytes(data), privateCert.LoadPrivateKeyFromCert(password));
    }

    public static byte[] SignDataByPrivateKey(string data, string privateCertPath, string? password)
    {
        return SignDataByPrivateKey(Encoding.UTF8.GetBytes(data), privateCertPath.LoadPrivateKeyFromCert(password));
    }

    public static byte[] SignDataByPrivateKey(string data, string privateKeyPath)
    {
        return SignDataByPrivateKey(Encoding.UTF8.GetBytes(data), privateKeyPath.GetKeyPairFromPem().Private);
    }

    public static byte[] SignDataByPrivateKey(byte[] data, string privateKeyPath)
    {
        return SignDataByPrivateKey(data, privateKeyPath.GetKeyPairFromPem().Private);
    }

    public static byte[] SignDataByPrivateKey(string data, AsymmetricKeyParameter privateKey)
    {
        return SignDataByPrivateKey(Encoding.UTF8.GetBytes(data), privateKey);
    }

    public static byte[] SignDataByPrivateKey(byte[] data, AsymmetricKeyParameter privateKey)
    {
        var signer = SignerUtilities.GetSigner("SHA256withRSA");
        signer.Init(true, privateKey);

        signer.BlockUpdate(data, 0, data.Length);

        return signer.GenerateSignature();
    }

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

        // Проверяем, что подпись сделана сертификатом, которым мы ожидали
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

            // Проверяем, что подпись сделана сертификатом, которым мы ожидали
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

    public static bool VerifyMatchBetweenPublicAndPrivateKeys(X509Certificate2 certificate1, X509Certificate2 certificate2)
    {
        // Получение публичных ключей из сертификатов
        var key1 = certificate1.GetRSAPublicKey();
        var key2 = certificate2.GetRSAPublicKey();

        if(key1 is null)
            throw new Exception("Certificate1 Cryptography public key could not be retrieved");

        if(key2 is null)
            throw new Exception("Certificate2 Cryptography public key could not be retrieved");

        // Сравнение модулей и экспонент
        var params1 = key1.ExportParameters(false);
        var params2 = key2.ExportParameters(false);

        return StructuralComparisons.StructuralEqualityComparer.Equals(params1.Modulus, params2.Modulus)
         && StructuralComparisons.StructuralEqualityComparer.Equals(params1.Exponent, params2.Exponent);
    }

    public static string EncryptDataWithPulicKey(string plaintext, AsymmetricKeyParameter publicKey)
    {
        var encryptEngine = new Pkcs1Encoding(new RsaEngine());
        encryptEngine.Init(true, publicKey);
        var plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
        var encryptedBytes = encryptEngine.ProcessBlock(plaintextBytes, 0, plaintextBytes.Length);

        return Convert.ToBase64String(encryptedBytes);
    }

    public static string DecryptDataWithPrivateKey(string ciphertext, AsymmetricKeyParameter privateKey)
    {
        var decryptEngine = new Pkcs1Encoding(new RsaEngine());
        decryptEngine.Init(false, privateKey);
        var ciphertextBytes = Convert.FromBase64String(ciphertext);
        var decryptedBytes = decryptEngine.ProcessBlock(ciphertextBytes, 0, ciphertextBytes.Length);

        return Encoding.UTF8.GetString(decryptedBytes);
    }
}