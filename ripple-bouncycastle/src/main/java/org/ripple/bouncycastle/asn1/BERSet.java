package org.ripple.bouncycastle.asn1;

import java.io.ioexception;
import java.util.enumeration;

public class berset
    extends asn1set
{
    /**
     * create an empty sequence
     */
    public berset()
    {
    }

    /**
     * @param obj - a single object that makes up the set.
     */
    public berset(
        asn1encodable obj)
    {
        super(obj);
    }

    /**
     * @param v - a vector of objects making up the set.
     */
    public berset(
        asn1encodablevector v)
    {
        super(v, false);
    }

    /**
     * create a set from an array of objects.
     */
    public berset(
        asn1encodable[]   a)
    {
        super(a, false);
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
        out.write(bertags.set | bertags.constructed);
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
