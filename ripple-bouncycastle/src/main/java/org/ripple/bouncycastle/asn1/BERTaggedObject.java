package org.ripple.bouncycastle.asn1;

import java.io.ioexception;
import java.util.enumeration;

/**
 * ber taggedobject - in asn.1 notation this is any object preceded by
 * a [n] where n is some number - these are assumed to follow the construction
 * rules (as with sequences).
 */
public class bertaggedobject
    extends asn1taggedobject
{
    /**
     * @param tagno the tag number for this object.
     * @param obj the tagged object.
     */
    public bertaggedobject(
        int             tagno,
        asn1encodable    obj)
    {
        super(true, tagno, obj);
    }

    /**
     * @param explicit true if an explicitly tagged object.
     * @param tagno the tag number for this object.
     * @param obj the tagged object.
     */
    public bertaggedobject(
        boolean         explicit,
        int             tagno,
        asn1encodable    obj)
    {
        super(explicit, tagno, obj);
    }

    /**
     * create an implicitly tagged object that contains a zero
     * length sequence.
     */
    public bertaggedobject(
        int             tagno)
    {
        super(false, tagno, new bersequence());
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
            asn1primitive primitive = obj.toasn1primitive();
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
        out.writetag(bertags.constructed | bertags.tagged, tagno);
        out.write(0x80);

        if (!empty)
        {
            if (!explicit)
            {
                enumeration e;
                if (obj instanceof asn1octetstring)
                {
                    if (obj instanceof beroctetstring)
                    {
                        e = ((beroctetstring)obj).getobjects();
                    }
                    else
                    {
                        asn1octetstring             octs = (asn1octetstring)obj;
                        beroctetstring bero = new beroctetstring(octs.getoctets());
                        e = bero.getobjects();
                    }
                }
                else if (obj instanceof asn1sequence)
                {
                    e = ((asn1sequence)obj).getobjects();
                }
                else if (obj instanceof asn1set)
                {
                    e = ((asn1set)obj).getobjects();
                }
                else
                {
                    throw new runtimeexception("not implemented: " + obj.getclass().getname());
                }

                while (e.hasmoreelements())
                {
                    out.writeobject((asn1encodable)e.nextelement());
                }
            }
            else
            {
                out.writeobject(obj);
            }
        }

        out.write(0x00);
        out.write(0x00);
    }
}
