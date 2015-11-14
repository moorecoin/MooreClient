package org.ripple.bouncycastle.crypto.tls;

/**
 * rfc 2246 6.1
 */
public class compressionmethod
{
    public static final short _null = 0;

    /**
     * @deprecated use '_null' instead
     */
    public static final short null = _null;

    /*
     * rfc 3749 2
     */
    public static final short deflate = 1;

    /*
     * values from 224 decimal (0xe0) through 255 decimal (0xff)
     * inclusive are reserved for private use.
     */
}
