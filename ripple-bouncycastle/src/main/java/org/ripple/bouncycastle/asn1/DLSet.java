package org.ripple.bouncycastle.asn1;

import java.io.ioexception;
import java.util.enumeration;

/**
 * a der encoded set object
 */
public class dlset
    extends asn1set
{
    private int bodylength = -1;

    /**
     * create an empty set
     */
    public dlset()
    {
    }

    /**
     * @param obj - a single object that makes up the set.
     */
    public dlset(
        asn1encodable obj)
    {
        super(obj);
    }

    /**
     * @param v - a vector of objects making up the set.
     */
    public dlset(
        asn1encodablevector v)
    {
        super(v, false);
    }

    /**
     * create a set from an array of objects.
     */
    public dlset(
        asn1encodable[] a)
    {
        super(a, false);
    }

    private int getbodylength()
        throws ioexception
    {
        if (bodylength < 0)
        {
            int length = 0;

            for (enumeration e = this.getobjects(); e.hasmoreelements();)
            {
                object    obj = e.nextelement();

                length += ((asn1encodable)obj).toasn1primitive().todlobject().encodedlength();
            }

            bodylength = length;
        }

        return bodylength;
    }

    int encodedlength()
        throws ioexception
    {
        int                     length = getbodylength();

        return 1 + streamutil.calculatebodylength(length) + length;
    }

    /*
     * a note on the implementation:
     * <p>
     * as dl requires the constructed, definite-length model to
     * be used for structured types, this varies slightly from the
     * asn.1 descriptions given. rather than just outputting set,
     * we also have to specify constructed, and the objects length.
     */
    void encode(
        asn1outputstream out)
        throws ioexception
    {
        asn1outputstream        dout = out.getdlsubstream();
        int                     length = getbodylength();

        out.write(bertags.set | bertags.constructed);
        out.writelength(length);

        for (enumeration e = this.getobjects(); e.hasmoreelements();)
        {
            object    obj = e.nextelement();

            dout.writeobject((asn1encodable)obj);
        }
    }
}
