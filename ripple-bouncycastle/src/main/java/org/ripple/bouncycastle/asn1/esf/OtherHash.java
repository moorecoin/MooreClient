package org.ripple.bouncycastle.asn1.esf;

import org.ripple.bouncycastle.asn1.asn1choice;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1octetstring;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.deroctetstring;
import org.ripple.bouncycastle.asn1.oiw.oiwobjectidentifiers;
import org.ripple.bouncycastle.asn1.x509.algorithmidentifier;

/**
 * <pre>
 * otherhash ::= choice {
 *    sha1hash  otherhashvalue, -- this contains a sha-1 hash
 *   otherhash  otherhashalgandvalue
 *  }
 * </pre>
 */
public class otherhash
    extends asn1object
    implements asn1choice
{

    private asn1octetstring sha1hash;
    private otherhashalgandvalue otherhash;

    public static otherhash getinstance(object obj)
    {
        if (obj instanceof otherhash)
        {
            return (otherhash)obj;
        }
        if (obj instanceof asn1octetstring)
        {
            return new otherhash((asn1octetstring)obj);
        }
        return new otherhash(otherhashalgandvalue.getinstance(obj));
    }

    private otherhash(asn1octetstring sha1hash)
    {
        this.sha1hash = sha1hash;
    }

    public otherhash(otherhashalgandvalue otherhash)
    {
        this.otherhash = otherhash;
    }

    public otherhash(byte[] sha1hash)
    {
        this.sha1hash = new deroctetstring(sha1hash);
    }

    public algorithmidentifier gethashalgorithm()
    {
        if (null == this.otherhash)
        {
            return new algorithmidentifier(oiwobjectidentifiers.idsha1);
        }
        return this.otherhash.gethashalgorithm();
    }

    public byte[] gethashvalue()
    {
        if (null == this.otherhash)
        {
            return this.sha1hash.getoctets();
        }
        return this.otherhash.gethashvalue().getoctets();
    }

    public asn1primitive toasn1primitive()
    {
        if (null == this.otherhash)
        {
            return this.sha1hash;
        }
        return this.otherhash.toasn1primitive();
    }
}
