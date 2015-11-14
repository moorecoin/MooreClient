package org.ripple.bouncycastle.asn1.pkcs;

import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.dertaggedobject;

public class crlbag
    extends asn1object
{
    private asn1objectidentifier crlid;
    private asn1encodable crlvalue;

    private crlbag(
        asn1sequence seq)
    {
        this.crlid = (asn1objectidentifier)seq.getobjectat(0);
        this.crlvalue = ((dertaggedobject)seq.getobjectat(1)).getobject();
    }

    public static crlbag getinstance(object o)
    {
        if (o instanceof crlbag)
        {
            return (crlbag)o;
        }
        else if (o != null)
        {
            return new crlbag(asn1sequence.getinstance(o));
        }

        return null;
    }

    public crlbag(
        asn1objectidentifier crlid,
        asn1encodable crlvalue)
    {
        this.crlid = crlid;
        this.crlvalue = crlvalue;
    }

    public asn1objectidentifier getcrlid()
    {
        return crlid;
    }

    public asn1encodable getcrlvalue()
    {
        return crlvalue;
    }

    /**
     * <pre>
     crlbag ::= sequence {
     crlid  bag-type.&id ({crltypes}),
     crlvalue  [0] explicit bag-type.&type ({crltypes}{@crlid})
     }

     x509crl bag-type ::= {octet string identified by {certtypes 1}
     -- der-encoded x.509 crl stored in octet string

     crltypes bag-type ::= {
     x509crl,
     ... -- for future extensions
     }
       </pre>
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector  v = new asn1encodablevector();

        v.add(crlid);
        v.add(new dertaggedobject(0, crlvalue));

        return new dersequence(v);
    }
}
