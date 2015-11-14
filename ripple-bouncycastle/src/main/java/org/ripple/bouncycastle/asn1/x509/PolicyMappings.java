package org.ripple.bouncycastle.asn1.x509;

import java.util.enumeration;
import java.util.hashtable;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.dersequence;

/**
 * policymappings v3 extension, described in rfc3280.
 * <pre>
 *    policymappings ::= sequence size (1..max) of sequence {
 *      issuerdomainpolicy      certpolicyid,
 *      subjectdomainpolicy     certpolicyid }
 * </pre>
 *
 * @see <a href="http://www.faqs.org/rfc/rfc3280.txt">rfc 3280, section 4.2.1.6</a>
 */
public class policymappings
    extends asn1object
{
    asn1sequence seq = null;

    public static policymappings getinstance(object obj)
    {
        if (obj instanceof policymappings)
        {
            return (policymappings)obj;
        }
        if (obj != null)
        {
            return new policymappings(asn1sequence.getinstance(obj));
        }

        return null;
    }

    /**
     * creates a new <code>policymappings</code> instance.
     *
     * @param seq an <code>asn1sequence</code> constructed as specified
     *            in rfc 3280
     */
    private policymappings(asn1sequence seq)
    {
        this.seq = seq;
    }

    /**
     * creates a new <code>policymappings</code> instance.
     *
     * @param mappings a <code>hashmap</code> value that maps
     *                 <code>string</code> oids
     *                 to other <code>string</code> oids.
     * @deprecated use certpolicyid constructors.
     */
    public policymappings(hashtable mappings)
    {
        asn1encodablevector dev = new asn1encodablevector();
        enumeration it = mappings.keys();

        while (it.hasmoreelements())
        {
            string idp = (string)it.nextelement();
            string sdp = (string)mappings.get(idp);
            asn1encodablevector dv = new asn1encodablevector();
            dv.add(new asn1objectidentifier(idp));
            dv.add(new asn1objectidentifier(sdp));
            dev.add(new dersequence(dv));
        }

        seq = new dersequence(dev);
    }

    public policymappings(certpolicyid issuerdomainpolicy, certpolicyid subjectdomainpolicy)
    {
        asn1encodablevector dv = new asn1encodablevector();
        dv.add(issuerdomainpolicy);
        dv.add(subjectdomainpolicy);

        seq = new dersequence(new dersequence(dv));
    }

    public policymappings(certpolicyid[] issuerdomainpolicy, certpolicyid[] subjectdomainpolicy)
    {
        asn1encodablevector dev = new asn1encodablevector();

        for (int i = 0; i != issuerdomainpolicy.length; i++)
        {
            asn1encodablevector dv = new asn1encodablevector();
            dv.add(issuerdomainpolicy[i]);
            dv.add(subjectdomainpolicy[i]);
            dev.add(new dersequence(dv));
        }

        seq = new dersequence(dev);
    }

    public asn1primitive toasn1primitive()
    {
        return seq;
    }
}
