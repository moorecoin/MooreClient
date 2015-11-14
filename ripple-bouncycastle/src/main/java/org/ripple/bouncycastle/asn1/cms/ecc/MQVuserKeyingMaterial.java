package org.ripple.bouncycastle.asn1.cms.ecc;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1octetstring;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.dertaggedobject;
import org.ripple.bouncycastle.asn1.cms.originatorpublickey;

public class mqvuserkeyingmaterial
    extends asn1object
{
    private originatorpublickey ephemeralpublickey;
    private asn1octetstring addedukm;

    public mqvuserkeyingmaterial(
        originatorpublickey ephemeralpublickey,
        asn1octetstring addedukm)
    {
        // todo check ephemeralpublickey not null
        
        this.ephemeralpublickey = ephemeralpublickey;
        this.addedukm = addedukm;
    }

    private mqvuserkeyingmaterial(
        asn1sequence seq)
    {
        // todo check seq has either 1 or 2 elements

        this.ephemeralpublickey = originatorpublickey.getinstance(
            seq.getobjectat(0));

        if (seq.size() > 1)
        {
            this.addedukm = asn1octetstring.getinstance(
                (asn1taggedobject)seq.getobjectat(1), true);
        }
    }

    /**
     * return an mqvuserkeyingmaterial object from a tagged object.
     *
     * @param obj      the tagged object holding the object we want.
     * @param explicit true if the object is meant to be explicitly
     *                 tagged false otherwise.
     * @throws illegalargumentexception if the object held by the
     *                                  tagged object cannot be converted.
     */
    public static mqvuserkeyingmaterial getinstance(
        asn1taggedobject obj,
        boolean explicit)
    {
        return getinstance(asn1sequence.getinstance(obj, explicit));
    }

    /**
     * return an mqvuserkeyingmaterial object from the given object.
     *
     * @param obj the object we want converted.
     * @throws illegalargumentexception if the object cannot be converted.
     */
    public static mqvuserkeyingmaterial getinstance(
        object obj)
    {
        if (obj == null || obj instanceof mqvuserkeyingmaterial)
        {
            return (mqvuserkeyingmaterial)obj;
        }

        if (obj instanceof asn1sequence)
        {
            return new mqvuserkeyingmaterial((asn1sequence)obj);
        }

        throw new illegalargumentexception("invalid mqvuserkeyingmaterial: " + obj.getclass().getname());
    }

    public originatorpublickey getephemeralpublickey()
    {
        return ephemeralpublickey;
    }

    public asn1octetstring getaddedukm()
    {
        return addedukm;
    }

    /**
     * produce an object suitable for an asn1outputstream.
     * <pre>
     * mqvuserkeyingmaterial ::= sequence {
     *   ephemeralpublickey originatorpublickey,
     *   addedukm [0] explicit userkeyingmaterial optional  }
     * </pre>
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector v = new asn1encodablevector();
        v.add(ephemeralpublickey);

        if (addedukm != null)
        {
            v.add(new dertaggedobject(true, 0, addedukm));
        }

        return new dersequence(v);
    }
}
