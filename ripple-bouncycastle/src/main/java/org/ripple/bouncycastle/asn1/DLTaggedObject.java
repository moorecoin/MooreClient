package org.ripple.bouncycastle.asn1;

import java.io.ioexception;

/**
 * definite length taggedobject - in asn.1 notation this is any object preceded by
 * a [n] where n is some number - these are assumed to follow the construction
 * rules (as with sequences).
 */
public class dltaggedobject
    extends asn1taggedobject
{
    private static final byte[] zero_bytes = new byte[0];

    /**
     * @param explicit true if an explicitly tagged object.
     * @param tagno the tag number for this object.
     * @param obj the tagged object.
     */
    public dltaggedobject(
        boolean explicit,
        int tagno,
        asn1encodable obj)
    {
        super(explicit, tagno, obj);
    }

    boolean isconstructed()
    {
        if (!empty)
        {
            if (explicit)
            {
                return true;
            }
            else
            {
                asn1primitive primitive = obj.toasn1primitive().todlobject();

                return primitive.isconstructed();
            }
        }
        else
        {
            return true;
        }
    }

    int encodedlength()
        throws ioexception
    {
        if (!empty)
        {
            int length = obj.toasn1primitive().todlobject().encodedlength();

            if (explicit)
            {
                return  streamutil.calculatetaglength(tagno) + streamutil.calculatebodylength(length) + length;
            }
            else
            {
                // header length already in calculation
                length = length - 1;

                return streamutil.calculatetaglength(tagno) + length;
            }
        }
        else
        {
            return streamutil.calculatetaglength(tagno) + 1;
        }
    }

    void encode(
        asn1outputstream out)
        throws ioexception
    {
        if (!empty)
        {
            asn1primitive primitive = obj.toasn1primitive().todlobject();

            if (explicit)
            {
                out.writetag(bertags.constructed | bertags.tagged, tagno);
                out.writelength(primitive.encodedlength());
                out.writeobject(primitive);
            }
            else
            {
                //
                // need to mark constructed types...
                //
                int flags;
                if (primitive.isconstructed())
                {
                    flags = bertags.constructed | bertags.tagged;
                }
                else
                {
                    flags = bertags.tagged;
                }

                out.writetag(flags, tagno);
                out.writeimplicitobject(primitive);
            }
        }
        else
        {
            out.writeencoded(bertags.constructed | bertags.tagged, tagno, zero_bytes);
        }
    }
}
