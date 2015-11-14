package org.ripple.bouncycastle.asn1.pkcs;

import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.x509.algorithmidentifier;

public class keyderivationfunc
    extends asn1object
{
    private algorithmidentifier algid;

    public keyderivationfunc(
        asn1objectidentifier objectid,
        asn1encodable parameters)
    {
        this.algid = new algorithmidentifier(objectid, parameters);
    }

    private keyderivationfunc(
        asn1sequence seq)
    {
        this.algid = algorithmidentifier.getinstance(seq);
    }

    public static final keyderivationfunc getinstance(object obj)
    {
        if (obj instanceof keyderivationfunc)
        {
            return (keyderivationfunc)obj;
        }
        else if (obj != null)
        {
            return new keyderivationfunc(asn1sequence.getinstance(obj));
        }

        return null;
    }

    public asn1objectidentifier getalgorithm()
    {
        return algid.getalgorithm();
    }

    public asn1encodable getparameters()
    {
        return algid.getparameters();
    }

    public asn1primitive toasn1primitive()
    {
        return algid.toasn1primitive();
    }
}
