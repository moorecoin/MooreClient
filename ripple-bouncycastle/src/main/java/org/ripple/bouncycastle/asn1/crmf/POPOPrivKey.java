package org.ripple.bouncycastle.asn1.crmf;

import org.ripple.bouncycastle.asn1.asn1choice;
import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.derbitstring;
import org.ripple.bouncycastle.asn1.dertaggedobject;
import org.ripple.bouncycastle.asn1.cms.envelopeddata;

public class popoprivkey
    extends asn1object
    implements asn1choice
{
    public static final int thismessage = 0;
    public static final int subsequentmessage = 1;
    public static final int dhmac = 2;
    public static final int agreemac = 3;
    public static final int encryptedkey = 4;

    private int tagno;
    private asn1encodable obj;

    private popoprivkey(asn1taggedobject obj)
    {
        this.tagno = obj.gettagno();

        switch (tagno)
        {
        case thismessage:
            this.obj = derbitstring.getinstance(obj, false);
            break;
        case subsequentmessage:
            this.obj = subsequentmessage.valueof(asn1integer.getinstance(obj, false).getvalue().intvalue());
            break;
        case dhmac:
            this.obj = derbitstring.getinstance(obj, false);
            break;
        case agreemac:
            this.obj = pkmacvalue.getinstance(obj, false);
            break;
        case encryptedkey:
            this.obj = envelopeddata.getinstance(obj, false);
            break;
        default:
            throw new illegalargumentexception("unknown tag in popoprivkey");
        }
    }

    public static popoprivkey getinstance(object obj)
    {
        if (obj instanceof popoprivkey)
        {
            return (popoprivkey)obj;
        }
        if (obj != null)
        {
            return new popoprivkey(asn1taggedobject.getinstance(obj));
        }

        return null;
    }

    public static popoprivkey getinstance(asn1taggedobject obj, boolean explicit)
    {
        return getinstance(asn1taggedobject.getinstance(obj, explicit));
    }

    public popoprivkey(subsequentmessage msg)
    {
        this.tagno = subsequentmessage;
        this.obj = msg;
    }

    public int gettype()
    {
        return tagno;
    }

    public asn1encodable getvalue()
    {
        return obj;
    }

    /**
     * <pre>
     * popoprivkey ::= choice {
     *        thismessage       [0] bit string,         -- deprecated
     *         -- possession is proven in this message (which contains the private
     *         -- key itself (encrypted for the ca))
     *        subsequentmessage [1] subsequentmessage,
     *         -- possession will be proven in a subsequent message
     *        dhmac             [2] bit string,         -- deprecated
     *        agreemac          [3] pkmacvalue,
     *        encryptedkey      [4] envelopeddata }
     * </pre>
     */
    public asn1primitive toasn1primitive()
    {
        return new dertaggedobject(false, tagno, obj);
    }
}
