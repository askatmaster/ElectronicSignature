namespace ElectronicSignature.Certification;

/// <summary>
/// An enumeration of the names of elliptic curves available in ECNamedCurveTable.
/// </summary>
public enum ECNamedCurve
{
    /// <summary>
    /// A curve with parameters defined by SEC 2, using prime number p=2^192-2^32-2^12-2^8-2^7-2^6-2^3-1.
    /// </summary>
    secp192k1,

    /// <summary>
    /// A curve with parameters defined by SEC 2, using prime number p=2^224-2^96+1.
    /// </summary>
    secp224k1,

    /// <summary>
    /// A curve with parameters defined by SEC 2, using prime number p=2^256-2^32-2^9-2^8-2^7-2^6-2^4-1.
    /// </summary>
    secp256k1,

    /// <summary>
    /// A curve with parameters defined by SEC 2, using prime number p=2^384-2^128-2^96+2^32-1.
    /// </summary>
    secp384r1,

    /// <summary>
    /// A curve with parameters defined by SEC 2, using prime number p=2^283-2^12-2^7-2^5-1.
    /// </summary>
    sect283k1
}