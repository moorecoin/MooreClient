package org.ripple.bouncycastle.crypto.tls;

/**
 * rfc 4492 5.1.1
 * <p/>
 * the named curves defined here are those specified in sec 2 [13]. note that many of these curves
 * are also recommended in ansi x9.62 [7] and fips 186-2 [11]. values 0xfe00 through 0xfeff are
 * reserved for private use. values 0xff01 and 0xff02 indicate that the client supports arbitrary
 * prime and characteristic-2 curves, respectively (the curve parameters must be encoded explicitly
 * in ecparameters).
 */
public class namedcurve
{
    public static final int sect163k1 = 1;
    public static final int sect163r1 = 2;
    public static final int sect163r2 = 3;
    public static final int sect193r1 = 4;
    public static final int sect193r2 = 5;
    public static final int sect233k1 = 6;
    public static final int sect233r1 = 7;
    public static final int sect239k1 = 8;
    public static final int sect283k1 = 9;
    public static final int sect283r1 = 10;
    public static final int sect409k1 = 11;
    public static final int sect409r1 = 12;
    public static final int sect571k1 = 13;
    public static final int sect571r1 = 14;
    public static final int secp160k1 = 15;
    public static final int secp160r1 = 16;
    public static final int secp160r2 = 17;
    public static final int secp192k1 = 18;
    public static final int secp192r1 = 19;
    public static final int secp224k1 = 20;
    public static final int secp224r1 = 21;
    public static final int secp256k1 = 22;
    public static final int secp256r1 = 23;
    public static final int secp384r1 = 24;
    public static final int secp521r1 = 25;

    /*
     * reserved (0xfe00..0xfeff)
     */

    public static final int arbitrary_explicit_prime_curves = 0xff01;
    public static final int arbitrary_explicit_char2_curves = 0xff02;

    public static boolean referstoaspecificnamedcurve(int namedcurve)
    {
        switch (namedcurve)
        {
        case arbitrary_explicit_prime_curves:
        case arbitrary_explicit_char2_curves:
            return false;
        default:
            return true;
        }
    }

}
