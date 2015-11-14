package org.ripple.bouncycastle.asn1.ess;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.x509.policyinformation;


public class signingcertificate
    extends asn1object
{
    asn1sequence certs;
    asn1sequence policies;

    public static signingcertificate getinstance(object o)
    {
        if (o instanceof signingcertificate)
        {
            return (signingcertificate) o;
        }
        else if (o != null)
        {
            return new signingcertificate(asn1sequence.getinstance(o));
        }

        return null;
    }

    /**
     * constructeurs
     */
    private signingcertificate(asn1sequence seq)
    {
        if (seq.size() < 1 || seq.size() > 2)
        {
            throw new illegalargumentexception("bad sequence size: "
                    + seq.size());
        }
        this.certs = asn1sequence.getinstance(seq.getobjectat(0));
        
        if (seq.size() > 1)
        {
            this.policies = asn1sequence.getinstance(seq.getobjectat(1));
        }
    }

    public signingcertificate(
        esscertid esscertid)
    {
        certs = new dersequence(esscertid);
    }

    public esscertid[] getcerts()
    {
        esscertid[] cs = new esscertid[certs.size()];
        
        for (int i = 0; i != certs.size(); i++)
        {
            cs[i] = esscertid.getinstance(certs.getobjectat(i));
        }
        
        return cs;
    }
    
    public policyinformation[] getpolicies()
    {
        if (policies == null)
        {
            return null;
        }
        
        policyinformation[] ps = new policyinformation[policies.size()];
        
        for (int i = 0; i != policies.size(); i++)
        {
            ps[i] = policyinformation.getinstance(policies.getobjectat(i));
        }
        
        return ps;
    }
    
    /**
     * the definition of signingcertificate is
     * <pre>
     * signingcertificate ::=  sequence {
     *      certs        sequence of esscertid,
     *      policies     sequence of policyinformation optional
     * }
     * </pre>
     * id-aa-signingcertificate object identifier ::= { iso(1)
     *  member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs9(9)
     *  smime(16) id-aa(2) 12 }
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector v = new asn1encodablevector();

        v.add(certs);
        
        if (policies != null)
        {
            v.add(policies);
        }
        
        return new dersequence(v);
    }
}
