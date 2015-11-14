package org.ripple.bouncycastle.asn1.eac;

import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.asn1sequence;

public abstract class publickeydataobject
    extends asn1object
{
    public static publickeydataobject getinstance(object obj)
    {
        if (obj instanceof publickeydataobject)
        {
            return (publickeydataobject)obj;
        }
        if (obj != null)
        {
            asn1sequence seq = asn1sequence.getinstance(obj);
            asn1objectidentifier usage = asn1objectidentifier.getinstance(seq.getobjectat(0));

            if (usage.on(eacobjectidentifiers.id_ta_ecdsa))
            {
                return new ecdsapublickey(seq);
            }
            else
            {
                return new rsapublickey(seq);
            }
        }

        return null;
    }

    public abstract asn1objectidentifier getusage();
}
