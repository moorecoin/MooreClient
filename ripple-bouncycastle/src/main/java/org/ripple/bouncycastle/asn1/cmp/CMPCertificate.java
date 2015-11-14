package org.ripple.bouncycastle.asn1.cmp;

import org.ripple.bouncycastle.asn1.asn1choice;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.dertaggedobject;
import org.ripple.bouncycastle.asn1.x509.attributecertificate;
import org.ripple.bouncycastle.asn1.x509.certificate;

public class cmpcertificate
    extends asn1object
    implements asn1choice
{
    private certificate x509v3pkcert;
    private attributecertificate x509v2attrcert;

    /**
     * note: the addition of attribute certificates is a bc extension.
     */
    public cmpcertificate(attributecertificate x509v2attrcert)
    {
        this.x509v2attrcert = x509v2attrcert;
    }

    public cmpcertificate(certificate x509v3pkcert)
    {
        if (x509v3pkcert.getversionnumber() != 3)
        {
            throw new illegalargumentexception("only version 3 certificates allowed");
        }

        this.x509v3pkcert = x509v3pkcert;
    }

    public static cmpcertificate getinstance(object o)
    {
        if (o == null || o instanceof cmpcertificate)
        {
            return (cmpcertificate)o;
        }

        if (o instanceof asn1sequence || o instanceof byte[])
        {
            return new cmpcertificate(certificate.getinstance(o));
        }

        if (o instanceof asn1taggedobject)
        {
            return new cmpcertificate(attributecertificate.getinstance(((asn1taggedobject)o).getobject()));
        }

        throw new illegalargumentexception("invalid object: " + o.getclass().getname());
    }

    public boolean isx509v3pkcert()
    {
         return x509v3pkcert != null;
    }

    public certificate getx509v3pkcert()
    {
        return x509v3pkcert;
    }

    public attributecertificate getx509v2attrcert()
    {
        return x509v2attrcert;
    }

    /**
     * <pre>
     * cmpcertificate ::= choice {
     *            x509v3pkcert        certificate
     *            x509v2attrcert      [1] attributecertificate
     *  }
     * </pre>
     * note: the addition of attribute certificates is a bc extension.
     *
     * @return a basic asn.1 object representation.
     */
    public asn1primitive toasn1primitive()
    {
        if (x509v2attrcert != null)
        {        // explicit following cmp conventions
            return new dertaggedobject(true, 1, x509v2attrcert);
        }

        return x509v3pkcert.toasn1primitive();
    }
}
