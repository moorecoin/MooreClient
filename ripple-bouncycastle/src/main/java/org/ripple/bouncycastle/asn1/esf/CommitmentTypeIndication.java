package org.ripple.bouncycastle.asn1.esf;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.dersequence;

public class commitmenttypeindication
    extends asn1object
{
    private asn1objectidentifier   commitmenttypeid;
    private asn1sequence          commitmenttypequalifier;
    
    private commitmenttypeindication(
        asn1sequence seq)
    {
        commitmenttypeid = (asn1objectidentifier)seq.getobjectat(0);

        if (seq.size() > 1)
        {
            commitmenttypequalifier = (asn1sequence)seq.getobjectat(1);
        }
    }

    public commitmenttypeindication(
        asn1objectidentifier commitmenttypeid)
    {
        this.commitmenttypeid = commitmenttypeid;
    }

    public commitmenttypeindication(
        asn1objectidentifier commitmenttypeid,
        asn1sequence        commitmenttypequalifier)
    {
        this.commitmenttypeid = commitmenttypeid;
        this.commitmenttypequalifier = commitmenttypequalifier;
    }

    public static commitmenttypeindication getinstance(
        object obj)
    {
        if (obj == null || obj instanceof commitmenttypeindication)
        {
            return (commitmenttypeindication)obj;
        }

        return new commitmenttypeindication(asn1sequence.getinstance(obj));
    }

    public asn1objectidentifier getcommitmenttypeid()
    {
        return commitmenttypeid;
    }
    
    public asn1sequence getcommitmenttypequalifier()
    {
        return commitmenttypequalifier;
    }
    
    /**
     * <pre>
     * commitmenttypeindication ::= sequence {
     *      commitmenttypeid   commitmenttypeidentifier,
     *      commitmenttypequalifier   sequence size (1..max) of
     *              commitmenttypequalifier optional }
     * </pre>
     */ 
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector v = new asn1encodablevector();
        
        v.add(commitmenttypeid);

        if (commitmenttypequalifier != null)
        {
            v.add(commitmenttypequalifier);
        }
        
        return new dersequence(v);
    }
}
