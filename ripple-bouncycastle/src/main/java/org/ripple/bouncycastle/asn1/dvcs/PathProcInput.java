package org.ripple.bouncycastle.asn1.dvcs;

import org.ripple.bouncycastle.asn1.asn1boolean;
import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.dertaggedobject;
import org.ripple.bouncycastle.asn1.x509.policyinformation;

/**
 * <pre>
 *     pathprocinput ::= sequence {
 *         acceptablepolicyset          sequence size (1..max) of
 *                                         policyinformation,
 *         inhibitpolicymapping         boolean default false,
 *         explicitpolicyreqd           [0] boolean default false ,
 *         inhibitanypolicy             [1] boolean default false
 *     }
 * </pre>
 */
public class pathprocinput
    extends asn1object
{

    private policyinformation[] acceptablepolicyset;
    private boolean inhibitpolicymapping = false;
    private boolean explicitpolicyreqd = false;
    private boolean inhibitanypolicy = false;

    public pathprocinput(policyinformation[] acceptablepolicyset)
    {
        this.acceptablepolicyset = acceptablepolicyset;
    }

    public pathprocinput(policyinformation[] acceptablepolicyset, boolean inhibitpolicymapping, boolean explicitpolicyreqd, boolean inhibitanypolicy)
    {
        this.acceptablepolicyset = acceptablepolicyset;
        this.inhibitpolicymapping = inhibitpolicymapping;
        this.explicitpolicyreqd = explicitpolicyreqd;
        this.inhibitanypolicy = inhibitanypolicy;
    }

    private static policyinformation[] fromsequence(asn1sequence seq)
    {
        policyinformation[] tmp = new policyinformation[seq.size()];

        for (int i = 0; i != tmp.length; i++)
        {
            tmp[i] = policyinformation.getinstance(seq.getobjectat(i));
        }

        return tmp;
    }

    public static pathprocinput getinstance(object obj)
    {
        if (obj instanceof pathprocinput)
        {
            return (pathprocinput)obj;
        }
        else if (obj != null)
        {
            asn1sequence seq = asn1sequence.getinstance(obj);
            asn1sequence policies = asn1sequence.getinstance(seq.getobjectat(0));
            pathprocinput result = new pathprocinput(fromsequence(policies));

            for (int i = 1; i < seq.size(); i++)
            {
                object o = seq.getobjectat(i);

                if (o instanceof asn1boolean)
                {
                    asn1boolean x = asn1boolean.getinstance(o);
                    result.setinhibitpolicymapping(x.istrue());
                }
                else if (o instanceof asn1taggedobject)
                {
                    asn1taggedobject t = asn1taggedobject.getinstance(o);
                    asn1boolean x;
                    switch (t.gettagno())
                    {
                    case 0:
                        x = asn1boolean.getinstance(t, false);
                        result.setexplicitpolicyreqd(x.istrue());
                        break;
                    case 1:
                        x = asn1boolean.getinstance(t, false);
                        result.setinhibitanypolicy(x.istrue());
                    }
                }
            }
            return result;
        }

        return null;
    }

    public static pathprocinput getinstance(
        asn1taggedobject obj,
        boolean explicit)
    {
        return getinstance(asn1sequence.getinstance(obj, explicit));
    }

    public asn1primitive toasn1primitive()
    {
        asn1encodablevector v = new asn1encodablevector();
        asn1encodablevector pv = new asn1encodablevector();

        for (int i = 0; i != acceptablepolicyset.length; i++)
        {
            pv.add(acceptablepolicyset[i]);
        }

        v.add(new dersequence(pv));

        if (inhibitpolicymapping)
        {
            v.add(new asn1boolean(inhibitpolicymapping));
        }
        if (explicitpolicyreqd)
        {
            v.add(new dertaggedobject(false, 0, new asn1boolean(explicitpolicyreqd)));
        }
        if (inhibitanypolicy)
        {
            v.add(new dertaggedobject(false, 1, new asn1boolean(inhibitanypolicy)));
        }

        return new dersequence(v);
    }

    public string tostring()
    {
        return "pathprocinput: {\n" +
            "acceptablepolicyset: " + acceptablepolicyset + "\n" +
            "inhibitpolicymapping: " + inhibitpolicymapping + "\n" +
            "explicitpolicyreqd: " + explicitpolicyreqd + "\n" +
            "inhibitanypolicy: " + inhibitanypolicy + "\n" +
            "}\n";
    }

    public policyinformation[] getacceptablepolicyset()
    {
        return acceptablepolicyset;
    }

    public boolean isinhibitpolicymapping()
    {
        return inhibitpolicymapping;
    }

    private void setinhibitpolicymapping(boolean inhibitpolicymapping)
    {
        this.inhibitpolicymapping = inhibitpolicymapping;
    }

    public boolean isexplicitpolicyreqd()
    {
        return explicitpolicyreqd;
    }

    private void setexplicitpolicyreqd(boolean explicitpolicyreqd)
    {
        this.explicitpolicyreqd = explicitpolicyreqd;
    }

    public boolean isinhibitanypolicy()
    {
        return inhibitanypolicy;
    }

    private void setinhibitanypolicy(boolean inhibitanypolicy)
    {
        this.inhibitanypolicy = inhibitanypolicy;
    }
}
