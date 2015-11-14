package org.ripple.bouncycastle.asn1.crmf;

import org.ripple.bouncycastle.asn1.asn1choice;
import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.dertaggedobject;
import org.ripple.bouncycastle.asn1.cms.envelopeddata;

public class encryptedkey
    extends asn1object
    implements asn1choice
{
    private envelopeddata envelopeddata;
    private encryptedvalue encryptedvalue;

    public static encryptedkey getinstance(object o)
    {
        if (o instanceof encryptedkey)
        {
            return (encryptedkey)o;
        }
        else if (o instanceof asn1taggedobject)
        {
            return new encryptedkey(envelopeddata.getinstance((asn1taggedobject)o, false));
        }
        else if (o instanceof encryptedvalue)
        {
            return new encryptedkey((encryptedvalue)o);
        }
        else
        {
            return new encryptedkey(encryptedvalue.getinstance(o));
        }
    }

    public encryptedkey(envelopeddata envelopeddata)
    {
        this.envelopeddata = envelopeddata;
    }

    public encryptedkey(encryptedvalue encryptedvalue)
    {
        this.encryptedvalue = encryptedvalue;
    }

    public boolean isencryptedvalue()
    {
        return encryptedvalue != null;
    }

    public asn1encodable getvalue()
    {
        if (encryptedvalue != null)
        {
            return encryptedvalue;
        }

        return envelopeddata;
    }

    /**
     * <pre>
     *    encryptedkey ::= choice {
     *        encryptedvalue        encryptedvalue, -- deprecated
     *        envelopeddata     [0] envelopeddata }
     *        -- the encrypted private key must be placed in the envelopeddata
     *        -- encryptedcontentinfo encryptedcontent octet string.
     * </pre>
     */
    public asn1primitive toasn1primitive()
    {
        if (encryptedvalue != null)
        {
            return encryptedvalue.toasn1primitive();
        }

        return new dertaggedobject(false, 0, envelopeddata);
    }
}
