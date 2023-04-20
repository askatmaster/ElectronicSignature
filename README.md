# ElectronicSignature

```dotnet add package ElectronicSignature --version 1.0.1```

A project for working with an electronic signature. Implements an add-on to the BouncyCastle library to work with RSA and ECDSA key pairs, as well as certificates.

This version provides functionality for working with key pairs of RSA and ECDSA algorithms.

Further in the instructions, a public certificate means a certificate containing only a public key, and a private certificate means a PFX certificate containing both private and public keys

### Possibilities
- Creating an RSA key pair
- ECDSA key pair creation
- Key pair processing
- Creation of CSR
- Creation of self-signed certificate
- Create PFX certificate
- Creating signed certificate
- Data encryption with public certificate and decryption with private certificate
- Data encryption with public key and decryption with private key
- Data signing with private certificate and extracting data from signature
- Data signing with private key and signature verification with public key
- Key pair integrity verification between public and private certificate
- Signature verification of private certificate by public certificate
- Signature verification of private certificate is trusted in trusted certificate storage
- Signature verification on the same certificate

In the Test console project there are demonstration methods.

```csharp
//The given code appears to be a sequence of function calls to various tests related to digital certificates, cryptography, and security.
//Let's break down each of these functions and their potential purpose.


//This test function could be generating a public-private key pair using the RSA encryption algorithm.
//This is a commonly used algorithm for generating secure keys and is often used for secure communication.
Tests.TestGenerateRSAKeyPair();

//This test function may be writing a key-pair to a file or creating a private and public keys.
//Private keys are used in asymmetric encryption, where one key is used for encryption and another key is used for decryption.
Tests.TestWriteKeyPairInPemFile();

//This test function may be generating a Certificate Signing Request (CSR), which is a message sent to a certificate authority to request a digital certificate.
Tests.TestGenerateCSR();

//This test function may be generating a self-signed certificate.
//Self-signed certificates are digital certificates that are signed by the same entity that issues the certificate.
Tests.TestGenerateSelfSignedCert();

//This test function could be creating a PFX file, which is a file format used to store private keys and certificates in a secure manner.
Tests.CreatePfx();

//This test function may be generating a signed certificate.
//A signed certificate is a digital certificate that has been signed by a trusted third-party, known as a certificate authority.
Tests.TestGenerateSignedCert();

//This test function may be decrypting data using a certificate.
//In asymmetric encryption, the public key is used for encryption and the private key is used for decryption.
Tests.TestDecryptWithCert();

//This test function may be decrypting data using a private key.
Tests.TestDecryptWithKey();

//This test function may be extracting a signed certificate from a private certificate.
Tests.TestExtractSignedByPrivateCert();

//This test function may be verifying that a certificate has been signed by a private key.
Tests.TestVerifySignedByPrivateKey();

//This test function may be verifying that the public key and the private key are a match.
Tests.TestVerifyMatchBetweenPublicAndPrivateKeys();

//This test function may be verifying that a certificate has been signed by a private certificate.
//ATTENTION!!! When this method is called, the result will be "flase" if any of the certificates under test are not in the trust store;
Tests.TestVerifySignedByPrivateCert();

//This test function may be verifying that signed data can be trusted using a root certificate.
//ATTENTION!!! When this method is called, the result will be "flase" if any of the certificates under test are not in the trust store;
Tests.TestVerifySignedDataRootCertAndTrustCommunication();

//This test function may be verifying that signed data can be trusted using the same certificate.
//ATTENTION!!! When this method is called, the result will be "flase" if any of the certificates under test are not in the trust store;
Tests.TestVerifySignedDataBySameCert();
```


#### Creating an RSA Key Pair

```csharp
var keyPair = Cryptography.GenerateRSAKeyPair();
keyPair.ToPemFile(keyPairPath);

Console.WriteLine(keyPair.Public.IsRSAKey());
```

#### Creating an ECDSA Key Pair

```csharp
var keyPair = Cryptography.GenerateECDSAKeyPair();
keyPair.ToPemFile(keyPairPath);

Console.WriteLine(keyPair.Public.IsECDSAKey());
```

#### Processing key pairs

The functionality of working with key pairs is presented in the form of extension methods in classes:
```PfxExtensions```, ```PemExtensions```, ```CertExtensions```.

К примеру:

Extension method for converting the key to base64 format
```csharp
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
```

Extension method for converting a key from base64 format to an object ```AsymmetricKeyParameter```
```csharp
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
```

#### Creating a CSR

```csharp
var keyPair = keyPairPath.GetKeyPairFromPem();
var csr = Cryptography.GenerateCSR("Test_KG", "Test_Chuy", "Test_Bishkek", "Test_osh", "Test_ITZone", "Test_Name", CryptographyAlgorithm.SHA256withRSA, keyPair);
csr.ToPemFile(csrPath);
```

#### To create a self-signed certificate

```csharp
var selfSignedCert = Cryptography.GenerateSelfSignedCert(csrPath.GetCSRPemFile(),
                                                         keyPairPath.GetPrivateKeyFromPem(),
                                                         DateTime.UtcNow,
                                                         DateTime.UtcNow.AddYears(1));
selfSignedCert.ToPemFile(selfSignedCertPath);
```

#### Creating a PFX certificate

```csharp
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
```

#### To create a signed certificate

```csharp
var signedCert = Cryptography.GenerateSignedCertificate(csrPath.GetCSRPemFile(),
                                                        privateCertPath.GetPrivateCert(privateCertPass),
                                                        privateCertPath,
                                                        DateTime.UtcNow,
                                                        DateTime.UtcNow.AddYears(1));
signedCert.ToPemFile(signedCertPath);
```

#### Encrypting data with a public certificate and decrypting it with a private certificate

```csharp
var message = "Hello world";
var encoded = Cryptography.EncryptDataByPublicCert(message, signedCertPath.GetPublicCert());
var data = Cryptography.DecryptDataWithPrivateCert(encoded, privateCertPath.GetPrivateCert(privateCertPass), privateCertPass);

Console.WriteLine(Encoding.UTF8.GetString(data));
```

#### Encrypting data with a public key and decrypting with a private key

```csharp
var message = "Hello world";
var keyPair = keyPairPath.GetKeyPairFromPem();
var encoded = Cryptography.EncryptDataWithPublicKey(message, keyPair.Public);
var data = Cryptography.DecryptDataWithPrivateKey(encoded, keyPair.Private);

Console.WriteLine(data);
```

#### Signing data with a private certificate and extracting data from the signature

```csharp
var message = "Hello world";
var signature = Cryptography.SignDataByPrivateCert(message, privateCertPath.GetPrivateCert(privateCertPass));

var data = Cryptography.ExtractSignedData(signature);
Console.WriteLine(Encoding.UTF8.GetString(data));
```

#### Signing data with a private key and verifying the signature with a public key

```csharp
var message = "Hello world";
var signature = Cryptography.SignDataByPrivateKey(message, privateKeyPath.GetPrivateKeyFromPem());

if(Cryptography.VerifySignedByPublicKey(message, signature, publicKeyPath.GetPublicKeyFromPem()))
    Console.WriteLine("True");
else
    Console.WriteLine("False");
```

#### Verify the integrity of the key pair between a public certificate and a private certificate

```csharp
var isValid = Cryptography.VerifyMatchBetweenPublicAndPrivateKeys(signedCertPath.GetPublicCert(),
                                                                  privateCertPath.GetPrivateCert(privateCertPass));

Console.WriteLine(isValid);
```

#### Verification of the signature of a private certificate with a public certificate

```csharp
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
```

#### Verify the signature of a private certificate yes trust in the trust store

```csharp
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
```

#### Verification of the signature on the same certificate

```csharp
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
```