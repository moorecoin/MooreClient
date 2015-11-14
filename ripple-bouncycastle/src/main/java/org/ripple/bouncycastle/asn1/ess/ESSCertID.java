package org.ripple.bouncycastle.asn1.ess;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1octetstring;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.deroctetstring;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.x509.issuerserial;

public class esscertid
    extends asn1object
{
    private asn1octetstring certhash;

    private issuerserial issuerserial;

    public static esscertid getinstance(object o)
    {
        if (o instanceof esscertid)
        {
            return (esscertid)o;
        }
        else if (o != null)
        {
            return new esscertid(asn1sequence.getinstance(o));
        }

        return null;
    }

    /**
     * constructor
     */
    private esscertid(asn1sequence seq)
    {
        if (seq.size() < 1 || seq.size() > 2)
        {
            throw new illegalargumentexception("bad sequence size: " + seq.size());
        }

        certhash = asn1octetstring.getinstance(seq.getobjectat(0));
 
        if (seq.size() > 1)
        {
            issuerserial = issuerserial.getinstance(seq.getobjectat(1));
        }
    }

    public esscertid(
        byte[]          hash)
    {
        certhash = new deroctetstring(hash);
    }

    public esscertid(
        byte[]          hash,
        issuerserial    issuerserial)
    {
        this.certhash = new deroctetstring(hash);
        this.issuerserial = issuerserial;
    }

    public byte[] getcerthash()
    {
        return certhash.getoctets();
    }

    public issuerserial getissuerserial()
    {
        return issuerserial;
    }

    /**
     * <pre>
     * esscertid ::= sequence {
     *     certhash hash, 
     *     issuerserial issuerserial optional }
     * </pre>
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector v = new asn1encodablevector();
        
        v.add(certhash);
        
        if (issuerserial != null)
        {
            v.add(issuerserial);
        }

        return new dersequence(v);
    }
}
