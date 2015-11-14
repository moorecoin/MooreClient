package org.ripple.bouncycastle.asn1.cms;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.x509.certificatelist;

public class timestampandcrl
    extends asn1object
{
    private contentinfo timestamp;
    private certificatelist crl;

    public timestampandcrl(contentinfo timestamp)
    {
        this.timestamp = timestamp;
    }

    private timestampandcrl(asn1sequence seq)
    {
        this.timestamp = contentinfo.getinstance(seq.getobjectat(0));
        if (seq.size() == 2)
        {
            this.crl = certificatelist.getinstance(seq.getobjectat(1));
        }
    }

    public static timestampandcrl getinstance(object obj)
    {
        if (obj instanceof timestampandcrl)
        {
            return (timestampandcrl)obj;
        }
        else if (obj != null)
        {
            return new timestampandcrl(asn1sequence.getinstance(obj));
        }

        return null;
    }

    public contentinfo gettimestamptoken()
    {
        return this.timestamp;
    }

    /** @deprecated use getcrl() */
    public certificatelist getcertificatelist()
    {
        return this.crl;
    }

    public certificatelist getcrl()
    {
        return this.crl;
    }

    /**
     * <pre>
     * timestampandcrl ::= sequence {
     *     timestamp   timestamptoken,          -- according to rfc 3161
     *     crl         certificatelist optional -- according to rfc 5280
     *  }
     * </pre>
     * @return
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector v = new asn1encodablevector();

        v.add(timestamp);

        if (crl != null)
        {
            v.add(crl);
        }

        return new dersequence(v);
    }
}
