package org.ripple.bouncycastle.crypto.tls;

/**
 * rfc 2246
 * <p/>
 * note that the values here are implementation-specific and arbitrary. it is recommended not to
 * depend on the particular values (e.g. serialization).
 */
public class ciphertype
{

    public static final int stream = 0;
    public static final int block = 1;

    /*
     * rfc 5246
     */
    public static final int aead = 2;
}
