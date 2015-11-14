package org.ripple.bouncycastle.asn1.ua;

import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1octetstring;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.deroctetstring;
import org.ripple.bouncycastle.math.ec.ecpoint;

public class dstu4145publickey
    extends asn1object
{

    private asn1octetstring pubkey;

    public dstu4145publickey(ecpoint pubkey)
    {
        // we always use big-endian in parameter encoding
        this.pubkey = new deroctetstring(dstu4145pointencoder.encodepoint(pubkey));
    }

    private dstu4145publickey(asn1octetstring ocstr)
    {
        pubkey = ocstr;
    }

    public static dstu4145publickey getinstance(object obj)
    {
        if (obj instanceof dstu4145publickey)
        {
            return (dstu4145publickey)obj;
        }

        if (obj != null)
        {
            return new dstu4145publickey(asn1octetstring.getinstance(obj));
        }

        return null;
    }

    public asn1primitive toasn1primitive()
    {
        return pubkey;
    }

}
