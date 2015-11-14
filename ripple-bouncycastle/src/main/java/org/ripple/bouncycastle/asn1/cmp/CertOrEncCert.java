package org.ripple.bouncycastle.asn1.cmp;

import org.ripple.bouncycastle.asn1.asn1choice;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.dertaggedobject;
import org.ripple.bouncycastle.asn1.crmf.encryptedvalue;

public class certorenccert
    extends asn1object
    implements asn1choice
{
    private cmpcertificate certificate;
    private encryptedvalue encryptedcert;

    private certorenccert(asn1taggedobject tagged)
    {
        if (tagged.gettagno() == 0)
        {
            certificate = cmpcertificate.getinstance(tagged.getobject());
        }
        else if (tagged.gettagno() == 1)
        {
            encryptedcert = encryptedvalue.getinstance(tagged.getobject());
        }
        else
        {
            throw new illegalargumentexception("unknown tag: " + tagged.gettagno());
        }
    }

    public static certorenccert getinstance(object o)
    {
        if (o instanceof certorenccert)
        {
            return (certorenccert)o;
        }

        if (o instanceof asn1taggedobject)
        {
            return new certorenccert((asn1taggedobject)o);
        }

        return null;
    }

    public certorenccert(cmpcertificate certificate)
    {
        if (certificate == null)
        {
            throw new illegalargumentexception("'certificate' cannot be null");
        }

        this.certificate = certificate;
    }

    public certorenccert(encryptedvalue encryptedcert)
    {
        if (encryptedcert == null)
        {
            throw new illegalargumentexception("'encryptedcert' cannot be null");
        }

        this.encryptedcert = encryptedcert;
    }

    public cmpcertificate getcertificate()
    {
        return certificate;
    }

    public encryptedvalue getencryptedcert()
    {
        return encryptedcert;
    }

    /**
     * <pre>
     * certorenccert ::= choice {
     *                      certificate     [0] cmpcertificate,
     *                      encryptedcert   [1] encryptedvalue
     *           }
     * </pre>
     * @return a basic asn.1 object representation.
     */
    public asn1primitive toasn1primitive()
    {
        if (certificate != null)
        {
            return new dertaggedobject(true, 0, certificate);
        }

        return new dertaggedobject(true, 1, encryptedcert);
    }
}
