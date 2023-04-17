namespace ElectronicSignature.Certification;

public enum CryptographyAlgorithm
{
    // Cryptography algorithms
    SHA1withRSA = 1, // NOT RECOMMENDED
    SHA224withRSA = 2,
    SHA256withRSA = 3,
    SHA384withRSA = 4,
    SHA512withRSA = 5,
    SHA3_224withRSA = 6,
    SHA3_256withRSA = 7,
    SHA3_384withRSA = 8,
    SHA3_512withRSA = 9,

    // ECDSA algorithms
    SHA1withECDSA = 10, // NOT RECOMMENDED
    SHA224withECDSA = 11,
    SHA256withECDSA = 12,
    SHA384withECDSA = 13,
    SHA512withECDSA = 14,
    SHA3_224withECDSA = 15,
    SHA3_256withECDSA = 16,
    SHA3_384withECDSA = 17,
    SHA3_512withECDSA = 18
}