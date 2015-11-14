package org.ripple.bouncycastle.asn1;

import java.io.ioexception;
import java.util.enumeration;

public class dersequence
    extends asn1sequence
{
    private int bodylength = -1;

    /**
     * create an empty sequence
     */
    public dersequence()
    {
    }

    /**
     * create a sequence containing one object
     */
    public dersequence(
        asn1encodable obj)
    {
        super(obj);
    }

    /**
     * create a sequence containing a vector of objects.
     */
    public dersequence(
        asn1encodablevector v)
    {
        super(v);
    }

    /**
     * create a sequence containing an array of objects.
     */
    public dersequence(
        asn1encodable[]   array)
    {
        super(array);
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

                length += ((asn1encodable)obj).toasn1primitive().toderobject().encodedlength();
            }

            bodylength = length;
        }

        return bodylength;
    }

    int encodedlength()
        throws ioexception
    {
        int length = getbodylength();

        return 1 + streamutil.calculatebodylength(length) + length;
    }

    /*
     * a note on the implementation:
     * <p>
     * as der requires the constructed, definite-length model to
     * be used for structured types, this varies slightly from the
     * asn.1 descriptions given. rather than just outputting sequence,
     * we also have to specify constructed, and the objects length.
     */
    void encode(
        asn1outputstream out)
        throws ioexception
    {
        asn1outputstream        dout = out.getdersubstream();
        int                     length = getbodylength();

        out.write(bertags.sequence | bertags.constructed);
        out.writelength(length);

        for (enumeration e = this.getobjects(); e.hasmoreelements();)
        {
            object    obj = e.nextelement();

            dout.writeobject((asn1encodable)obj);
        }
    }
}
