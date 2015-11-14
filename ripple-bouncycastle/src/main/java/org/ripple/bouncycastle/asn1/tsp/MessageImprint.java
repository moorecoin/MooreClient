package org.ripple.bouncycastle.asn1.tsp;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1octetstring;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.deroctetstring;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.x509.algorithmidentifier;

public class messageimprint
    extends asn1object
{
    algorithmidentifier hashalgorithm;
    byte[]              hashedmessage;
    
    /**
     * @param o
     * @return a messageimprint object.
     */
    public static messageimprint getinstance(object o)
    {
        if (o instanceof messageimprint)
        {
            return (messageimprint)o;
        }

        if (o != null)
        {
            return new messageimprint(asn1sequence.getinstance(o));
        }

        return null;
    }
    
    private messageimprint(
        asn1sequence seq)
    {
        this.hashalgorithm = algorithmidentifier.getinstance(seq.getobjectat(0));
        this.hashedmessage = asn1octetstring.getinstance(seq.getobjectat(1)).getoctets();
    }
    
    public messageimprint(
        algorithmidentifier hashalgorithm,
        byte[]              hashedmessage)
    {
        this.hashalgorithm = hashalgorithm;
        this.hashedmessage = hashedmessage;
    }
    
    public algorithmidentifier gethashalgorithm()
    {
        return hashalgorithm;
    }
    
    public byte[] gethashedmessage()
    {
        return hashedmessage;
    }
    
    /**
     * <pre>
     *    messageimprint ::= sequence  {
     *       hashalgorithm                algorithmidentifier,
     *       hashedmessage                octet string  }
     * </pre>
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector v = new asn1encodablevector();

        v.add(hashalgorithm);
        v.add(new deroctetstring(hashedmessage));

        return new dersequence(v);
    }
}
