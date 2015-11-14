package org.ripple.bouncycastle.asn1.pkcs;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.bersequence;
import org.ripple.bouncycastle.asn1.dlsequence;

public class authenticatedsafe
    extends asn1object
{
    private contentinfo[]    info;
    private boolean  isber = true;

    private authenticatedsafe(
        asn1sequence  seq)
    {
        info = new contentinfo[seq.size()];

        for (int i = 0; i != info.length; i++)
        {
            info[i] = contentinfo.getinstance(seq.getobjectat(i));
        }

        isber = seq instanceof bersequence;
    }

    public static authenticatedsafe getinstance(
        object o)
    {
        if (o instanceof authenticatedsafe)
        {
            return (authenticatedsafe)o;
        }

        if (o != null)
        {
            return new authenticatedsafe(asn1sequence.getinstance(o));
        }

        return null;
    }

    public authenticatedsafe(
        contentinfo[]       info)
    {
        this.info = info;
    }

    public contentinfo[] getcontentinfo()
    {
        return info;
    }

    public asn1primitive toasn1primitive()
    {
        asn1encodablevector v = new asn1encodablevector();

        for (int i = 0; i != info.length; i++)
        {
            v.add(info[i]);
        }

        if (isber)
        {
            return new bersequence(v);
        }
        else
        {
            return new dlsequence(v);
        }
    }
}
