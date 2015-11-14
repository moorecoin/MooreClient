package org.ripple.bouncycastle.crypto.tls;

public class srtpprotectionprofile
{
    /*
     * rfc 5764 4.1.2.
     */
    public static final int srtp_aes128_cm_hmac_sha1_80 = 0x0001;
    public static final int srtp_aes128_cm_hmac_sha1_32 = 0x0002;
    public static final int srtp_null_hmac_sha1_80 = 0x0005;
    public static final int srtp_null_hmac_sha1_32 = 0x0006;
}
