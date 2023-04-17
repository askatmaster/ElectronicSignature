using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
namespace ElectronicSignature.Certification;

public static class PemExtensions
{
    public static void ToPemFile(this object key, string fileName)
    {
        using (var privateKeyWriter = new StreamWriter(fileName))
        {
            var pemWriter = new PemWriter(privateKeyWriter);
            pemWriter.WriteObject(key);
        }
    }

    public static void ToPemFile(this AsymmetricCipherKeyPair key, string fileName)
    {
        using (var privateKeyWriter = new StreamWriter(fileName))
        {
            var pemWriter = new PemWriter(privateKeyWriter);
            pemWriter.WriteObject(key.Private);
            pemWriter.WriteObject(key.Public);
        }
    }

    public static T GetFromPemFile<T>(this string pemFilePath)
    {
        using (var reader = new StreamReader(pemFilePath))
        {
            var pemReader = new PemReader(reader);
            return (T)pemReader.ReadObject();
        }
    }

    public static Pkcs10CertificationRequest GetCSRPemFile(this string pemFilePath)
    {
        using (var reader = new StreamReader(pemFilePath))
        {
            var pemReader = new PemReader(reader);
            return (Pkcs10CertificationRequest)pemReader.ReadObject();
        }
    }

    public static AsymmetricCipherKeyPair GetKeyPairFromPem(this string pemFilePath)
    {
        using (var reader = new StreamReader(pemFilePath))
        {
            var pemReader = new PemReader(reader);
            return (AsymmetricCipherKeyPair)pemReader.ReadObject();
        }
    }

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

    public static AsymmetricKeyParameter GetPublickKeyFromPem(this string publicKeyPath)
    {
        using (var reader = new StreamReader(publicKeyPath))
        {
            var pemReader = new PemReader(reader);
            var obj = pemReader.ReadObject();

            if (obj is RsaKeyParameters keyPair)
            {
                if(keyPair.IsPrivate)
                    throw new Exception("The provided file contain a private key.");

                return keyPair;
            }

            throw new InvalidOperationException("The provided file does not contain a public key.");
        }
    }
}