package org.ripple.bouncycastle.asn1;

import java.io.bytearrayoutputstream;
import java.io.ioexception;

public abstract class asn1object
    implements asn1encodable
{
    /**
     * return the default ber or der encoding for this object.
     *
     * @return ber/der byte encoded object.
     * @throws java.io.ioexception on encoding error.
     */
    public byte[] getencoded()
        throws ioexception
    {
        bytearrayoutputstream bout = new bytearrayoutputstream();
        asn1outputstream      aout = new asn1outputstream(bout);

        aout.writeobject(this);

        return bout.tobytearray();
    }

    /**
     * return either the default for "ber" or a der encoding if "der" is specified.
     *
     * @param encoding name of encoding to use.
     * @return byte encoded object.
     * @throws ioexception on encoding error.
     */
    public byte[] getencoded(
        string encoding)
        throws ioexception
    {
        if (encoding.equals(asn1encoding.der))
        {
            bytearrayoutputstream   bout = new bytearrayoutputstream();
            deroutputstream         dout = new deroutputstream(bout);

            dout.writeobject(this);

            return bout.tobytearray();
        }
        else if (encoding.equals(asn1encoding.dl))
        {
            bytearrayoutputstream   bout = new bytearrayoutputstream();
            dloutputstream          dout = new dloutputstream(bout);

            dout.writeobject(this);

            return bout.tobytearray();
        }

        return this.getencoded();
    }

    public int hashcode()
    {
        return this.toasn1primitive().hashcode();
    }

    public boolean equals(
        object  o)
    {
        if (this == o)
        {
            return true;
        }

        if (!(o instanceof asn1encodable))
        {
            return false;
        }

        asn1encodable other = (asn1encodable)o;

        return this.toasn1primitive().equals(other.toasn1primitive());
    }

    /**
     * @deprecated use toasn1primitive()
     * @return the underlying primitive type.
     */
    public asn1primitive toasn1object()
    {
        return this.toasn1primitive();
    }

    protected static boolean hasencodedtagvalue(object obj, int tagvalue)
    {
        return (obj instanceof byte[]) && ((byte[])obj)[0] == tagvalue;
    }

    public abstract asn1primitive toasn1primitive();
}
