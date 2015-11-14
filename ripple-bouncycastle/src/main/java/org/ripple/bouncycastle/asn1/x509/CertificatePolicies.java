package org.ripple.bouncycastle.asn1.x509;

import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.dersequence;

public class certificatepolicies
    extends asn1object
{
    private final policyinformation[] policyinformation;

    public static certificatepolicies getinstance(
        object  obj)
    {
        if (obj instanceof certificatepolicies)
        {
            return (certificatepolicies)obj;
        }

        if (obj != null)
        {
            return new certificatepolicies(asn1sequence.getinstance(obj));
        }

        return null;
    }

    public static certificatepolicies getinstance(
        asn1taggedobject obj,
        boolean          explicit)
    {
        return getinstance(asn1sequence.getinstance(obj, explicit));
    }

    /**
     * construct a certificatepolicies object containing one policyinformation.
     * 
     * @param name the name to be contained.
     */
    public certificatepolicies(
        policyinformation  name)
    {
        this.policyinformation = new policyinformation[] { name };
    }

    public certificatepolicies(
        policyinformation[] policyinformation)
    {
        this.policyinformation = policyinformation;
    }

    private certificatepolicies(
        asn1sequence  seq)
    {
        this.policyinformation = new policyinformation[seq.size()];

        for (int i = 0; i != seq.size(); i++)
        {
            policyinformation[i] = policyinformation.getinstance(seq.getobjectat(i));
        }
    }

    public policyinformation[] getpolicyinformation()
    {
        policyinformation[] tmp = new policyinformation[policyinformation.length];

        system.arraycopy(policyinformation, 0, tmp, 0, policyinformation.length);

        return tmp;
    }

    /**
     * produce an object suitable for an asn1outputstream.
     * <pre>
     * certificatepolicies ::= sequence size {1..max} of policyinformation
     * </pre>
     */
    public asn1primitive toasn1primitive()
    {
        return new dersequence(policyinformation);
    }

    public string tostring()
    {
        string p = null;
        for (int i = 0; i < policyinformation.length; i++)
        {
            if (p != null)
            {
                p += ", ";
            }
            p += policyinformation[i];
        }

        return "certificatepolicies: " + p;
    }
}
