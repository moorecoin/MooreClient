package org.ripple.bouncycastle.asn1.esf;

import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.deria5string;

public class spuri
{
    private deria5string uri;

    public static spuri getinstance(
        object obj)
    {
        if (obj instanceof spuri)
        {
            return (spuri) obj;
        }
        else if (obj instanceof deria5string)
        {
            return new spuri(deria5string.getinstance(obj));
        }

        return null;
    }

    public spuri(
        deria5string uri)
    {
        this.uri = uri;
    }

    public deria5string geturi()
    {
        return uri;
    }

    /**
     * <pre>
     * spuri ::= ia5string
     * </pre>
     */
    public asn1primitive toasn1primitive()
    {
        return uri.toasn1primitive();
    }
}
