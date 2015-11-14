package org.ripple.bouncycastle.asn1.esf;

import java.util.enumeration;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.dertaggedobject;
import org.ripple.bouncycastle.asn1.x509.attribute;
import org.ripple.bouncycastle.asn1.x509.attributecertificate;


public class signerattribute
    extends asn1object
{
    private object[] values;

    public static signerattribute getinstance(
        object o)
    {
        if (o instanceof signerattribute)
        {
            return (signerattribute) o;
        }
        else if (o != null)
        {
            return new signerattribute(asn1sequence.getinstance(o));
        }

        return null;
    }

    private signerattribute(
        asn1sequence seq)
    {
        int index = 0;
        values = new object[seq.size()];

        for (enumeration e = seq.getobjects(); e.hasmoreelements();)
        {
            asn1taggedobject taggedobject = asn1taggedobject.getinstance(e.nextelement());

            if (taggedobject.gettagno() == 0)
            {
                asn1sequence attrs = asn1sequence.getinstance(taggedobject, true);
                attribute[]  attributes = new attribute[attrs.size()];

                for (int i = 0; i != attributes.length; i++)
                {
                    attributes[i] = attribute.getinstance(attrs.getobjectat(i));
                }
                values[index] = attributes;
            }
            else if (taggedobject.gettagno() == 1)
            {
                values[index] = attributecertificate.getinstance(asn1sequence.getinstance(taggedobject, true));
            }
            else
            {
                throw new illegalargumentexception("illegal tag: " + taggedobject.gettagno());
            }
            index++;
        }
    }

    public signerattribute(
        attribute[] claimedattributes)
    {
        this.values = new object[1];
        this.values[0] = claimedattributes;
    }

    public signerattribute(
        attributecertificate certifiedattributes)
    {
        this.values = new object[1];
        this.values[0] = certifiedattributes;
    }

    /**
     * return the sequence of choices - the array elements will either be of
     * type attribute[] or attributecertificate depending on what tag was used.
     *
     * @return array of choices.
     */
    public object[] getvalues()
    {
        return values;
    }

    /**
     *
     * <pre>
     *  signerattribute ::= sequence of choice {
     *      claimedattributes   [0] claimedattributes,
     *      certifiedattributes [1] certifiedattributes }
     *
     *  claimedattributes ::= sequence of attribute
     *  certifiedattributes ::= attributecertificate -- as defined in rfc 3281: see clause 4.1.
     * </pre>
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector v = new asn1encodablevector();

        for (int i = 0; i != values.length; i++)
        {
            if (values[i] instanceof attribute[])
            {
                v.add(new dertaggedobject(0, new dersequence((attribute[])values[i])));
            }
            else
            {
                v.add(new dertaggedobject(1, (attributecertificate)values[i]));
            }
        }

        return new dersequence(v);
    }
}
