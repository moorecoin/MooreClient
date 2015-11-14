package org.ripple.bouncycastle.asn1;

import java.io.ioexception;

public abstract class asn1primitive
    extends asn1object
{
    asn1primitive()
    {

    }

    /**
     * create a base asn.1 object from a byte stream.
     *
     * @param data the byte stream to parse.
     * @return the base asn.1 object represented by the byte stream.
     * @exception ioexception if there is a problem parsing the data.
     */
    public static asn1primitive frombytearray(byte[] data)
        throws ioexception
    {
        asn1inputstream ain = new asn1inputstream(data);

        try
        {
            return ain.readobject();
        }
        catch (classcastexception e)
        {
            throw new ioexception("cannot recognise object in stream");
        }
    }

    public final boolean equals(object o)
    {
        if (this == o)
        {
            return true;
        }

        return (o instanceof asn1encodable) && asn1equals(((asn1encodable)o).toasn1primitive());
    }

    public asn1primitive toasn1primitive()
    {
        return this;
    }

    asn1primitive toderobject()
    {
        return this;
    }

    asn1primitive todlobject()
    {
        return this;
    }

    public abstract int hashcode();

    abstract boolean isconstructed();

    abstract int encodedlength() throws ioexception;

    abstract void encode(asn1outputstream out) throws ioexception;

    abstract boolean asn1equals(asn1primitive o);
}