package org.ripple.bouncycastle.crypto.tls;

/**
 * rfc 5246 7.4.1.4.1 (in rfc 2246, there were no specific values assigned)
 */
public class signaturealgorithm
{

    public static final short anonymous = 0;
    public static final short rsa = 1;
    public static final short dsa = 2;
    public static final short ecdsa = 3;
}
