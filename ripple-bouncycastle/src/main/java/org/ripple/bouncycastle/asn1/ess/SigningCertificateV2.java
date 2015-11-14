package org.ripple.bouncycastle.asn1.ess;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.x509.policyinformation;

public class signingcertificatev2
    extends asn1object
{
    asn1sequence certs;
    asn1sequence policies;

    public static signingcertificatev2 getinstance(
        object o)
    {
        if (o == null || o instanceof signingcertificatev2)
        {
            return (signingcertificatev2) o;
        }
        else if (o instanceof asn1sequence)
        {
            return new signingcertificatev2((asn1sequence) o);
        }

        return null;
    }

    private signingcertificatev2(
        asn1sequence seq)
    {
        if (seq.size() < 1 || seq.size() > 2)
        {
            throw new illegalargumentexception("bad sequence size: " + seq.size());
        }

        this.certs = asn1sequence.getinstance(seq.getobjectat(0));

        if (seq.size() > 1)
        {
            this.policies = asn1sequence.getinstance(seq.getobjectat(1));
        }
    }

    public signingcertificatev2(
        esscertidv2 cert)
    {
        this.certs = new dersequence(cert);
    }

    public signingcertificatev2(
        esscertidv2[] certs)
    {
        asn1encodablevector v = new asn1encodablevector();
        for (int i=0; i < certs.length; i++)
        {
            v.add(certs[i]);
        }
        this.certs = new dersequence(v);
    }

    public signingcertificatev2(
        esscertidv2[] certs,
        policyinformation[] policies)
    {
        asn1encodablevector v = new asn1encodablevector();
        for (int i=0; i < certs.length; i++)
        {
            v.add(certs[i]);
        }
        this.certs = new dersequence(v);

        if (policies != null)
        {
            v = new asn1encodablevector();
            for (int i=0; i < policies.length; i++)
            {
                v.add(policies[i]);
            }
            this.policies = new dersequence(v);
        }
    }

    public esscertidv2[] getcerts()
    {
        esscertidv2[] certids = new esscertidv2[certs.size()];
        for (int i = 0; i != certs.size(); i++)
        {
            certids[i] = esscertidv2.getinstance(certs.getobjectat(i));
        }
        return certids;
    }

    public policyinformation[] getpolicies()
    {
        if (policies == null)
        {
            return null;
        }

        policyinformation[] policyinformations = new policyinformation[policies.size()];
        for (int i = 0; i != policies.size(); i++)
        {
            policyinformations[i] = policyinformation.getinstance(policies.getobjectat(i));
        }
        return policyinformations;
    }

    /**
     * the definition of signingcertificatev2 is
     * <pre>
     * signingcertificatev2 ::=  sequence {
     *      certs        sequence of esscertidv2,
     *      policies     sequence of policyinformation optional
     * }
     * </pre>
     * id-aa-signingcertificatev2 object identifier ::= { iso(1)
     *    member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs9(9)
     *    smime(16) id-aa(2) 47 }
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
