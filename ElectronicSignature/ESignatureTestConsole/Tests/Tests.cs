using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using ElectronicSignature.Certification;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
namespace ESignatureTestConsole.Tests;

public static class Tests
{
    private static readonly string keyPairPath = @"rsaKeyPair.pem";
    private static readonly string privateKeyPath = @"rsaPrivateKey.pem";
    private static readonly string publicKeyPath = @"rsaPublicKey.pem";
    private static readonly string csrPath = @"rsaCSR.pem";
    private static readonly string signedCertPath = @"rsaSignedCert.pem";
    private static readonly string selfSignedCertPath = @"selfSignedCert.pem";
    private static readonly string privateCertPath = @"privateCert.pfx";
    private static readonly string privateCertPass = "1234";

    /// <summary>
    /// This test function could be generating a public-private key pair using the RSA encryption algorithm.
    /// This is a commonly used algorithm for generating secure keys and is often used for secure communication.
    /// </summary>
    public static void TestGenerateRSAKeyPair()
    {
        var keyPair = Cryptography.GenerateRSAKeyPair();
        keyPair.ToPemFile(keyPairPath);

        Console.WriteLine(keyPair.Public.IsRSAKey());
    }

    /// <summary>
    /// This test function could be generating a public-private key pair using the ECDSA encryption algorithm.
    /// This is a commonly used algorithm for generating secure keys and is often used for secure communication.
    /// </summary>
    public static void TestGenerateECDSAKeyPair()
    {
        var keyPair = Cryptography.GenerateECDSAKeyPair();
        keyPair.ToPemFile(keyPairPath);

        Console.WriteLine(keyPair.Public.IsECDSAKey());
    }

    /// <summary>
    /// This test function may be writing a key-pair to a file or creating a private and public keys.
    /// Private keys are used in asymmetric encryption, where one key is used for encryption and another key is used for decryption.
    /// </summary>
    public static void TestWriteKeyPairInPemFile()
    {
        var keyPair = keyPairPath.GetKeyPairFromPem();
        keyPair.Private.ToPemFile(privateKeyPath);
        keyPair.Public.ToPemFile(publicKeyPath);
    }

    /// <summary>
    /// This test function may be generating a Certificate Signing Request (CSR), which is a message sent to a certificate authority to request a digital certificate.
    /// </summary>
    public static void TestGenerateCSR()
    {
        var keyPair = keyPairPath.GetKeyPairFromPem();
        var csr = Cryptography.GenerateCSR("Test_KG", "Test_Chuy", "Test_Bishkek", "Test_osh", "Test_ITZone", "Test_Name", CryptographyAlgorithm.SHA256withRSA, keyPair);
        csr.ToPemFile(csrPath);
    }

    /// <summary>
    /// This test function may be generating a self-signed certificate.
    /// Self-signed certificates are digital certificates that are signed by the same entity that issues the certificate.
    /// </summary>
    public static void TestGenerateSelfSignedCert()
    {
        var selfSignedCert = Cryptography.GenerateSelfSignedCert(csrPath.GetCSRPemFile(),
                                                                 keyPairPath.GetPrivateKeyFromPem(),
                                                                 DateTime.UtcNow,
                                                                 DateTime.UtcNow.AddYears(1));
        selfSignedCert.ToPemFile(selfSignedCertPath);
    }

    /// <summary>
    /// This test function may be generating a signed certificate.
    /// A signed certificate is a digital certificate that has been signed by a trusted third-party, known as a certificate authority.
    /// </summary>
    public static void TestGenerateSignedCert()
    {
        var signedCert = Cryptography.GenerateSignedCertificate(csrPath.GetCSRPemFile(),
                                                                privateCertPath.GetPrivateCert(privateCertPass),
                                                                privateCertPath,
                                                                DateTime.UtcNow,
                                                                DateTime.UtcNow.AddYears(1));
        signedCert.ToPemFile(signedCertPath);
    }

    /// <summary>
    /// This test function may be verifying that a certificate has been signed by a private key.
    /// </summary>
    public static void TestVerifySignedByPrivateKey()
    {
        var message = "Hello world";
        var signature = Cryptography.SignDataByPrivateKey(message, privateKeyPath.GetPrivateKeyFromPem());

        if(Cryptography.VerifySignedByPublicKey(message, signature, publicKeyPath.GetPublicKeyFromPem()))
            Console.WriteLine("True");
        else
            Console.WriteLine("False");
    }

    /// <summary>
    /// This test function may be verifying that a certificate has been signed by a private certificate.
    /// </summary>
    public static void TestVerifySignedByPrivateCert()
    {
        var message = "Hello world";
        var signature = Cryptography.SignDataByPrivateCert(message, privateCertPath.GetPrivateCert(privateCertPass));

        if(Cryptography.VerifySignedDataByCertIssuer(signature, signedCertPath.GetPublicCert(), out var data))
        {
            if (data != null)
                Console.WriteLine(Encoding.UTF8.GetString(data));
        }
        else
        {
            Console.WriteLine("False");
        }
    }

    /// <summary>
    /// This test function may be extracting a signed certificate from a private certificate.
    /// </summary>
    public static void TestExtractSignedByPrivateCert()
    {
        var message = "Hello world";
        var signature = Cryptography.SignDataByPrivateCert(message, privateCertPath.GetPrivateCert(privateCertPass));

        var data = Cryptography.ExtractSignedData(signature);
        Console.WriteLine(Encoding.UTF8.GetString(data));
    }

    /// <summary>
    /// This test function may be decrypting data using a certificate.
    /// In asymmetric encryption, the public key is used for encryption and the private key is used for decryption.
    /// </summary>
    public static void TestDecryptWithCert()
    {
        var message = "Hello world";
        var encoded = Cryptography.EncryptDataByPublicCert(message, signedCertPath.GetPublicCert());
        var data = Cryptography.DecryptDataWithPrivateCert(encoded, privateCertPath.GetPrivateCert(privateCertPass), privateCertPass);

        Console.WriteLine(Encoding.UTF8.GetString(data));
    }

    //This test function may be decrypting data using a private key.
    public static void TestDecryptWithKey()
    {
        var message = "Hello world";
        var keyPair = keyPairPath.GetKeyPairFromPem();
        var encoded = Cryptography.EncryptDataWithPulicKey(message, keyPair.Public);
        var data = Cryptography.DecryptDataWithPrivateKey(encoded, keyPair.Private);

        Console.WriteLine(data);
    }

    /// <summary>
    /// This test function could be creating a PFX file, which is a file format used to store private keys and certificates in a secure manner.
    /// </summary>
    public static void CreatePfx()
    {
        var certificate = new X509Certificate2(selfSignedCertPath);
        var keyPair = keyPairPath.GetKeyPairFromPem();

        var bcRsaPrivateKey = (RsaPrivateCrtKeyParameters)keyPair.Private;
        var rsaParameters = DotNetUtilities.ToRSAParameters(bcRsaPrivateKey);
        var rsaKey = RSA.Create(rsaParameters);

        // Assuming you have an X509Certificate2 named certificate
        var exportableCertificate = certificate.CopyWithPrivateKey(rsaKey);

        // Create password for certificate protection
        var passwordForCertificateProtection = new SecureString();

        foreach (var @char in "1234")
            passwordForCertificateProtection.AppendChar(@char);

        // Export certificate to a file.
        File.WriteAllBytes(privateCertPath, exportableCertificate.Export(X509ContentType.Pfx, passwordForCertificateProtection));
    }

    /// <summary>
    /// This test function may be verifying that signed data can be trusted using the same certificate.
    /// </summary>
    public static void TestVerifySignedDataBySameCert()
    {
        var message = "Hello world";
        var signature = Cryptography.SignDataByPrivateCert(message, privateCertPath.GetPrivateCert(privateCertPass));

        if(Cryptography.VerifySignedDataBySameCert(signature, privateCertPath.GetPrivateCert(privateCertPass), out var data))
        {
            if (data != null)
                Console.WriteLine(Encoding.UTF8.GetString(data));
        }
        else
        {
            Console.WriteLine("False");
        }
    }

    /// <summary>
    /// This test function may be verifying that signed data can be trusted using a root certificate.
    /// </summary>
    public static void TestVerifySignedDataRootCertAndTrustCommunication()
    {
        var message = "Hello world";
        var signature = Cryptography.SignDataByPrivateCert(message, privateCertPath.GetPrivateCert(privateCertPass));

        if(Cryptography.VerifySignedDataRootCertAndTrustCommunication(signature, privateCertPath.GetPrivateCert(privateCertPass), out var data))
        {
            if (data != null)
                Console.WriteLine(Encoding.UTF8.GetString(data));
        }
        else
        {
            Console.WriteLine("False");
        }
    }

    /// <summary>
    /// This test function may be verifying that the public key and the private key are a match.
    /// </summary>
    public static void TestVerifyMatchBetweenPublicAndPrivateKeys()
    {
        var isValid = Cryptography.VerifyMatchBetweenPublicAndPrivateKeys(signedCertPath.GetPublicCert(), privateCertPath.GetPrivateCert(privateCertPass));

        Console.WriteLine(isValid);
    }

    /// <summary>
    /// Tests the GetCompressedECDSAPublicKeyFromBase64 method by providing a Base64-encoded compressed ECDSA public key
    /// and checking if the retrieved key is not private.
    /// </summary>
    public static void TestGetCompressedECDSAPublicKeyFromBase64()
    {
        var key = "A2srIPKCMgOVyXq/fhK5Wnr3A/w9cfDv7dEepWZAKglw".GetCompressedECDSAPublicKeyFromBase64();

        Console.WriteLine(!key.IsPrivate);
    }

    /// <summary>
    /// Tests the GetCompressedECDSAPublicKeyFromPem method by providing a PEM-formatted compressed ECDSA public key
    /// and checking if the imported key is not private.
    /// </summary>
    public static void TestImportCompressedECDSAPublicKeyFromPem()
    {
        var compressedKeyAsPem = @"-----BEGIN EC PUBLIC KEY-----A2srIPKCMgOVyXq/fhK5Wnr3A/w9cfDv7dEepWZAKglw-----END EC PUBLIC KEY-----";

        var key = compressedKeyAsPem.GetCompressedECDSAPublicKeyFromPem();

        Console.WriteLine(!key.IsPrivate);
    }
}