package org.ripple.bouncycastle.crypto.tls;

/**
 * rfc 5246
 * <p/>
 * note that the values here are implementation-specific and arbitrary. it is recommended not to
 * depend on the particular values (e.g. serialization).
 */
public class prfalgorithm
{

    /*
     * placeholder to refer to the legacy tls algorithm
     */
    public static final int tls_prf_legacy = 0;

    public static final int tls_prf_sha256 = 1;

    /*
     * implied by rfc 5288
     */
    public static final int tls_prf_sha384 = 2;
}
