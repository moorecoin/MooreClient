package org.ripple.bouncycastle.crypto.tls;

/**
 * rfc 2246
 * <p/>
 * note that the values here are implementation-specific and arbitrary. it is recommended not to
 * depend on the particular values (e.g. serialization).
 */
public class keyexchangealgorithm
{
    public static final int null = 0;
    public static final int rsa = 1;
    public static final int rsa_export = 2;
    public static final int dhe_dss = 3;
    public static final int dhe_dss_export = 4;
    public static final int dhe_rsa = 5;
    public static final int dhe_rsa_export = 6;
    public static final int dh_dss = 7;
    public static final int dh_dss_export = 8;
    public static final int dh_rsa = 9;
    public static final int dh_rsa_export = 10;
    public static final int dh_anon = 11;
    public static final int dh_anon_export = 12;

    /*
     * rfc 4279
     */
    public static final int psk = 13;
    public static final int dhe_psk = 14;
    public static final int rsa_psk = 15;

    /*
     * rfc 4429
     */
    public static final int ecdh_ecdsa = 16;
    public static final int ecdhe_ecdsa = 17;
    public static final int ecdh_rsa = 18;
    public static final int ecdhe_rsa = 19;
    public static final int ecdh_anon = 20;

    /*
     * rfc 5054
     */
    public static final int srp = 21;
    public static final int srp_dss = 22;
    public static final int srp_rsa = 23;
}
