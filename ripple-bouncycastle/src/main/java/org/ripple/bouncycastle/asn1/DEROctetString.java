package org.ripple.bouncycastle.asn1;

import java.io.ioexception;

public class deroctetstring
    extends asn1octetstring
{
    /**
     * @param string the octets making up the octet string.
     */
    public deroctetstring(
        byte[]  string)
    {
        super(string);
    }

    public deroctetstring(
        asn1encodable obj)
        throws ioexception
    {
        super(obj.toasn1primitive().getencoded(asn1encoding.der));
    }

    boolean isconstructed()
    {
        return false;
    }

    int encodedlength()
    {
        return 1 + streamutil.calculatebodylength(string.length) + string.length;
    }

    void encode(
        asn1outputstream out)
        throws ioexception
    {
        out.writeencoded(bertags.octet_string, string);
    }

    static void encode(
        deroutputstream derout,
        byte[]          bytes)
        throws ioexception
    {
        derout.writeencoded(bertags.octet_string, bytes);
    }
}
