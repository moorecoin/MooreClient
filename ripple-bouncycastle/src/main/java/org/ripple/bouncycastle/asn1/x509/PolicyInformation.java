package org.ripple.bouncycastle.asn1.x509;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.dersequence;

public class policyinformation
    extends asn1object
{
    private asn1objectidentifier   policyidentifier;
    private asn1sequence          policyqualifiers;

    private policyinformation(
        asn1sequence seq)
    {
        if (seq.size() < 1 || seq.size() > 2)
        {
            throw new illegalargumentexception("bad sequence size: "
                    + seq.size());
        }

        policyidentifier = asn1objectidentifier.getinstance(seq.getobjectat(0));

        if (seq.size() > 1)
        {
            policyqualifiers = asn1sequence.getinstance(seq.getobjectat(1));
        }
    }

    public policyinformation(
        asn1objectidentifier policyidentifier)
    {
        this.policyidentifier = policyidentifier;
    }

    public policyinformation(
        asn1objectidentifier policyidentifier,
        asn1sequence        policyqualifiers)
    {
        this.policyidentifier = policyidentifier;
        this.policyqualifiers = policyqualifiers;
    }

    public static policyinformation getinstance(
        object obj)
    {
        if (obj == null || obj instanceof policyinformation)
        {
            return (policyinformation)obj;
        }

        return new policyinformation(asn1sequence.getinstance(obj));
    }

    public asn1objectidentifier getpolicyidentifier()
    {
        return policyidentifier;
    }
    
    public asn1sequence getpolicyqualifiers()
    {
        return policyqualifiers;
    }
    
    /* 
     * policyinformation ::= sequence {
     *      policyidentifier   certpolicyid,
     *      policyqualifiers   sequence size (1..max) of
     *              policyqualifierinfo optional }
     */ 
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector v = new asn1encodablevector();
        
        v.add(policyidentifier);

        if (policyqualifiers != null)
        {
            v.add(policyqualifiers);
        }
        
        return new dersequence(v);
    }
}
