package org.ripple.bouncycastle.crypto.tls;

public class clientcertificatetype
{

    /*
     *  rfc 4346 7.4.4
     */
    public static final short rsa_sign = 1;
    public static final short dss_sign = 2;
    public static final short rsa_fixed_dh = 3;
    public static final short dss_fixed_dh = 4;
    public static final short rsa_ephemeral_dh_reserved = 5;
    public static final short dss_ephemeral_dh_reserved = 6;
    public static final short fortezza_dms_reserved = 20;

    /*
     * rfc 4492 5.5
     */
    public static final short ecdsa_sign = 64;
    public static final short rsa_fixed_ecdh = 65;
    public static final short ecdsa_fixed_ecdh = 66;
}
