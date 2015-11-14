package org.ripple.bouncycastle.asn1.crmf;

import org.ripple.bouncycastle.asn1.asn1choice;
import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.dernull;
import org.ripple.bouncycastle.asn1.dertaggedobject;

public class proofofpossession
    extends asn1object
    implements asn1choice
{
    public static final int type_ra_verified = 0;
    public static final int type_signing_key = 1;
    public static final int type_key_encipherment = 2;
    public static final int type_key_agreement = 3;

    private int tagno;
    private asn1encodable obj;

    private proofofpossession(asn1taggedobject tagged)
    {
        tagno = tagged.gettagno();
        switch (tagno)
        {
        case 0:
            obj = dernull.instance;
            break;
        case 1:
            obj = poposigningkey.getinstance(tagged, false);
            break;
        case 2:
        case 3:
            obj = popoprivkey.getinstance(tagged, true);
            break;
        default:
            throw new illegalargumentexception("unknown tag: " + tagno);
        }
    }

    public static proofofpossession getinstance(object o)
    {
        if (o == null || o instanceof proofofpossession)
        {
            return (proofofpossession)o;
        }

        if (o instanceof asn1taggedobject)
        {
            return new proofofpossession((asn1taggedobject)o);
        }

        throw new illegalargumentexception("invalid object: " + o.getclass().getname());
    }

    /** creates a proofofpossession with type raverified. */
    public proofofpossession()
    {
        tagno = type_ra_verified;
        obj = dernull.instance;
    }

    /** creates a proofofpossession for a signing key. */
    public proofofpossession(poposigningkey poposk)
    {
        tagno = type_signing_key;
        obj = poposk;
    }

    /**
     * creates a proofofpossession for key encipherment or agreement.
     * @param type one of type_key_encipherment or type_key_agreement
     */
    public proofofpossession(int type, popoprivkey privkey)
    {
        tagno = type;
        obj = privkey;
    }

    public int gettype()
    {
        return tagno;
    }

    public asn1encodable getobject()
    {
        return obj;
    }

    /**
     * <pre>
     * proofofpossession ::= choice {
     *                           raverified        [0] null,
     *                           -- used if the ra has already verified that the requester is in
     *                           -- possession of the private key
     *                           signature         [1] poposigningkey,
     *                           keyencipherment   [2] popoprivkey,
     *                           keyagreement      [3] popoprivkey }
     * </pre>
     * @return a basic asn.1 object representation.
     */
    public asn1primitive toasn1primitive()
    {
        return new dertaggedobject(false, tagno, obj);
    }
}
