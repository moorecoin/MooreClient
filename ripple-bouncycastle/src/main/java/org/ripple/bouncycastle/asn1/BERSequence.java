package org.ripple.bouncycastle.asn1;

import java.io.ioexception;
import java.util.enumeration;

public class bersequence
    extends asn1sequence
{
    /**
     * create an empty sequence
     */
    public bersequence()
    {
    }

    /**
     * create a sequence containing one object
     */
    public bersequence(
        asn1encodable obj)
    {
        super(obj);
    }

    /**
     * create a sequence containing a vector of objects.
     */
    public bersequence(
        asn1encodablevector v)
    {
        super(v);
    }

    /**
     * create a sequence containing an array of objects.
     */
    public bersequence(
        asn1encodable[]   array)
    {
        super(array);
    }

    int encodedlength()
        throws ioexception
    {
        int length = 0;
        for (enumeration e = getobjects(); e.hasmoreelements();)
        {
            length += ((asn1encodable)e.nextelement()).toasn1primitive().encodedlength();
        }

        return 2 + length + 2;
    }

    /*
     */
    void encode(
        asn1outputstream out)
        throws ioexception
    {
        out.write(bertags.sequence | bertags.constructed);
        out.write(0x80);

        enumeration e = getobjects();
        while (e.hasmoreelements())
        {
            out.writeobject((asn1encodable)e.nextelement());
        }

        out.write(0x00);
        out.write(0x00);
    }
}
