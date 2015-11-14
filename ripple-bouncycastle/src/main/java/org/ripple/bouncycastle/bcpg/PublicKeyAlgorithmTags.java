package org.ripple.bouncycastle.bcpg;

/**
 * public key algorithm tag numbers
 */
public interface publickeyalgorithmtags 
{
    public static final int rsa_general = 1;       // rsa (encrypt or sign)
    public static final int rsa_encrypt = 2;       // rsa encrypt-only
    public static final int rsa_sign = 3;          // rsa sign-only
    public static final int elgamal_encrypt = 16;  // elgamal (encrypt-only), see [elgamal]
    public static final int dsa = 17;              // dsa (digital signature standard)
    public static final int ec = 18;               // reserved for elliptic curve
    public static final int ecdsa = 19;            // reserved for ecdsa
    public static final int elgamal_general = 20;  // elgamal (encrypt or sign)
    public static final int diffie_hellman = 21;   // reserved for diffie-hellman (x9.42, as defined for ietf-s/mime)

    public static final int experimental_1 = 100;
    public static final int experimental_2 = 101;
    public static final int experimental_3 = 102;
    public static final int experimental_4 = 103;
    public static final int experimental_5 = 104;
    public static final int experimental_6 = 105;
    public static final int experimental_7 = 106;
    public static final int experimental_8 = 107;
    public static final int experimental_9 = 108;
    public static final int experimental_10 = 109;
    public static final int experimental_11 = 110;
}
