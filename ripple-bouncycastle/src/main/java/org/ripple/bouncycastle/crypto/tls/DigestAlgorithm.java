package org.ripple.bouncycastle.crypto.tls;

/**
 * rfc 2246
 * <p/>
 * note that the values here are implementation-specific and arbitrary. it is recommended not to
 * depend on the particular values (e.g. serialization).
 *
 * @deprecated use macalgorithm constants instead
 */
public class digestalgorithm
{
    public static final int null = 0;
    public static final int md5 = 1;
    public static final int sha = 2;

    /*
     * rfc 5246
     */
    public static final int sha256 = 3;
    public static final int sha384 = 4;
    public static final int sha512 = 5;
}
