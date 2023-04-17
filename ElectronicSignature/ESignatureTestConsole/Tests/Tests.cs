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
    private static readonly string keyPairPath = @"tests/rsaKeyPair.pem";
    private static readonly string privateKeyPath = @"tests/rsaPrivateKey.pem";
    private static readonly string publicKeyPath = @"tests/rsaPublicKey.pem";
    private static readonly string csrPath = @"tests/rsaCSR.pem";
    private static readonly string signedCertPath = @"tests/rsaSignedCert.pem";
    private static readonly string selfSignedCertPath = @"tests/selfSignedCert.pem";
    private static readonly string privateCertPath = @"tests/privateCert.pfx";
    private static readonly string privateCertPass = "1234";

    public static void TestGenerateRSAKeyPair()
    {
        var keyPair = Cryptography.GenerateRSAKeyPair();
        keyPair.ToPemFile(keyPairPath);
    }

    public static void TestWriteCreatePrivateKey()
    {
        var keyPair = keyPairPath.GetKeyPairFromPem();
        keyPair.Private.ToPemFile(privateKeyPath);
        keyPair.Public.ToPemFile(publicKeyPath);
    }

    public static void TestGenerateCSR()
    {
        var keyPair = keyPairPath.GetKeyPairFromPem();
        var csr = Cryptography.GenerateCSR("Test_KG", "Test_Chuy", "Test_Bishkek", "Test_osh", "Test_ITZone", "Test_Name", CryptographyAlgorithm.SHA256withRSA, keyPair);
        csr.ToPemFile(csrPath);
    }

    public static void TestGenerateSelfSignedCert()
    {
        var selfSignedCert = Cryptography.GenerateSelfSignedCert(csrPath.GetCSRPemFile(),
                                                                 keyPairPath.GetPrivateKeyFromPem(),
                                                                 DateTime.UtcNow,
                                                                 DateTime.UtcNow.AddYears(1));
        selfSignedCert.ToPemFile(selfSignedCertPath);
    }

    public static void TestGenerateSignedCert()
    {
        var signedCert = Cryptography.GenerateSignedCertificate(csrPath.GetCSRPemFile(),
                                                                privateCertPath.GetPrivateCert(privateCertPass),
                                                                privateCertPath,
                                                                DateTime.UtcNow,
                                                                DateTime.UtcNow.AddYears(1));
        signedCert.ToPemFile(signedCertPath);
    }

    public static void TestVerifySignedByPrivateKey()
    {
        var message = "Hello world";
        var signature = Cryptography.SignDataByPrivateKey(message, privateKeyPath.GetPrivateKeyFromPem());

        if(Cryptography.VerifySignedByPublicKey(message, signature, publicKeyPath.GetPublickKeyFromPem()))
            Console.WriteLine("True");
        else
            Console.WriteLine("False");
    }

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

    public static void TestExtractSignedByPrivateCert()
    {
        var message = "Hello world";
        var signature = Cryptography.SignDataByPrivateCert(message, privateCertPath.GetPrivateCert(privateCertPass));

        var data = Cryptography.ExtractSignedData(signature);
        Console.WriteLine(Encoding.UTF8.GetString(data));
    }

    public static void TestDecryptWithCert()
    {
        var message = "Hello world";
        var encoded = Cryptography.EncryptDataByPublicCert(message, signedCertPath.GetPublicCert());
        var data = Cryptography.DecryptDataWithPrivateCert(encoded, privateCertPath.GetPrivateCert(privateCertPass), privateCertPass);

        Console.WriteLine(Encoding.UTF8.GetString(data));
    }

    public static void TestDecryptWithKey()
    {
        var message = "Hello world";
        var keyPair = keyPairPath.GetKeyPairFromPem();
        var encoded = Cryptography.EncryptDataWithPulicKey(message, keyPair.Public);
        var data = Cryptography.DecryptDataWithPrivateKey(encoded, keyPair.Private);

        Console.WriteLine(data);
    }

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

    public static void TestVerifyMatchBetweenPublicAndPrivateKeys()
    {
        var dasd = Cryptography.VerifyMatchBetweenPublicAndPrivateKeys(signedCertPath.GetPublicCert(), privateCertPath.GetPrivateCert(privateCertPass));

        Console.WriteLine(dasd);
    }
}