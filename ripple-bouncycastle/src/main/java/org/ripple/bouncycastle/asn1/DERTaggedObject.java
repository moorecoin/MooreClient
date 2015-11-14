package org.ripple.bouncycastle.asn1;

import java.io.ioexception;

/**
 * der taggedobject - in asn.1 notation this is any object preceded by
 * a [n] where n is some number - these are assumed to follow the construction
 * rules (as with sequences).
 */
public class dertaggedobject
    extends asn1taggedobject
{
    private static final byte[] zero_bytes = new byte[0];

    /**
     * @param explicit true if an explicitly tagged object.
     * @param tagno the tag number for this object.
     * @param obj the tagged object.
     */
    public dertaggedobject(
        boolean       explicit,
        int           tagno,
        asn1encodable obj)
    {
        super(explicit, tagno, obj);
    }

    public dertaggedobject(int tagno, asn1encodable encodable)
    {
        super(true, tagno, encodable);
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
                asn1primitive primitive = obj.toasn1primitive().toderobject();

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
            asn1primitive primitive = obj.toasn1primitive().toderobject();
            int length = primitive.encodedlength();

            if (explicit)
            {
                return streamutil.calculatetaglength(tagno) + streamutil.calculatebodylength(length) + length;
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
            asn1primitive primitive = obj.toasn1primitive().toderobject();

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
