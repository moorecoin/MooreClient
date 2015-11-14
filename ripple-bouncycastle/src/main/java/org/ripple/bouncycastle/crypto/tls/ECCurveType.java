package org.ripple.bouncycastle.crypto.tls;

/**
 * rfc 4492 5.4
 */
public class eccurvetype
{
    /**
     * indicates the elliptic curve domain parameters are conveyed verbosely, and the
     * underlying finite field is a prime field.
     */
    public static final short explicit_prime = 1;

    /**
     * indicates the elliptic curve domain parameters are conveyed verbosely, and the
     * underlying finite field is a characteristic-2 field.
     */
    public static final short explicit_char2 = 2;

    /**
     * indicates that a named curve is used. this option should be used when applicable.
     */
    public static final short named_curve = 3;

    /*
     * values 248 through 255 are reserved for private use.
     */
}
