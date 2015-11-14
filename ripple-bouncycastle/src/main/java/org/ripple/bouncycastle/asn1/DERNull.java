package org.ripple.bouncycastle.asn1;

import java.io.ioexception;

/**
 * a null object.
 */
public class dernull
    extends asn1null
{
    public static final dernull instance = new dernull();

    private static final byte[]  zerobytes = new byte[0];

    /**
     * @deprecated use dernull.instance
     */
    public dernull()
    {
    }

    boolean isconstructed()
    {
        return false;
    }

    int encodedlength()
    {
        return 2;
    }

    void encode(
        asn1outputstream out)
        throws ioexception
    {
        out.writeencoded(bertags.null, zerobytes);
    }
}
