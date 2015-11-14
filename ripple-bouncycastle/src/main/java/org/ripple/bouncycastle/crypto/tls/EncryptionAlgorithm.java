package org.ripple.bouncycastle.crypto.tls;

/**
 * rfc 2246
 * <p/>
 * note that the values here are implementation-specific and arbitrary. it is recommended not to
 * depend on the particular values (e.g. serialization).
 */
public class encryptionalgorithm
{

    public static final int null = 0;
    public static final int rc4_40 = 1;
    public static final int rc4_128 = 2;
    public static final int rc2_cbc_40 = 3;
    public static final int idea_cbc = 4;
    public static final int des40_cbc = 5;
    public static final int des_cbc = 6;
    public static final int _3des_ede_cbc = 7;

    /*
     * rfc 3268
     */
    public static final int aes_128_cbc = 8;
    public static final int aes_256_cbc = 9;

    /*
     * rfc 4132
     */
    public static final int camellia_128_cbc = 12;
    public static final int camellia_256_cbc = 13;

    /*
     * rfc 4162
     */
    public static final int seed_cbc = 14;

    /*
     * rfc 5289
     */
    public static final int aes_128_gcm = 10;
    public static final int aes_256_gcm = 11;
}
