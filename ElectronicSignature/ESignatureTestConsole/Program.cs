using ESignatureTestConsole.Tests;
Console.WriteLine("Hello, ElectronicSignature!");

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

