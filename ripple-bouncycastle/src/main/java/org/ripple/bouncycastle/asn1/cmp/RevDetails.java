package org.ripple.bouncycastle.asn1.cmp;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.crmf.certtemplate;
import org.ripple.bouncycastle.asn1.x509.extensions;
import org.ripple.bouncycastle.asn1.x509.x509extensions;

public class revdetails
    extends asn1object
{
    private certtemplate certdetails;
    private extensions crlentrydetails;

    private revdetails(asn1sequence seq)
    {
        certdetails = certtemplate.getinstance(seq.getobjectat(0));
        if  (seq.size() > 1)
        {
            crlentrydetails = extensions.getinstance(seq.getobjectat(1));
        }
    }

    public static revdetails getinstance(object o)
    {
        if (o instanceof revdetails)
        {
            return (revdetails)o;
        }

        if (o != null)
        {
            return new revdetails(asn1sequence.getinstance(o));
        }

        return null;
    }

    public revdetails(certtemplate certdetails)
    {
        this.certdetails = certdetails;
    }

    /**
     * @deprecated use method taking extensions
     * @param certdetails
     * @param crlentrydetails
     */
    public revdetails(certtemplate certdetails, x509extensions crlentrydetails)
    {
        this.certdetails = certdetails;
        this.crlentrydetails = extensions.getinstance(crlentrydetails.toasn1primitive());
    }

    public revdetails(certtemplate certdetails, extensions crlentrydetails)
    {
        this.certdetails = certdetails;
        this.crlentrydetails = crlentrydetails;
    }

    public certtemplate getcertdetails()
    {
        return certdetails;
    }

    public extensions getcrlentrydetails()
    {
        return crlentrydetails;
    }

    /**
     * <pre>
     * revdetails ::= sequence {
     *                  certdetails         certtemplate,
     *                   -- allows requester to specify as much as they can about
     *                   -- the cert. for which revocation is requested
     *                   -- (e.g., for cases in which serialnumber is not available)
     *                   crlentrydetails     extensions       optional
     *                   -- requested crlentryextensions
     *             }
     * </pre>
     * @return a basic asn.1 object representation.
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector v = new asn1encodablevector();

        v.add(certdetails);

        if (crlentrydetails != null)
        {
            v.add(crlentrydetails);
        }

        return new dersequence(v);
    }
}
