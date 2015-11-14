package org.ripple.bouncycastle.asn1.cmp;

import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.x509.certificatelist;

public class crlanncontent
    extends asn1object
{
    private asn1sequence content;

    private crlanncontent(asn1sequence seq)
    {
        content = seq;
    }

    public static crlanncontent getinstance(object o)
    {
        if (o instanceof crlanncontent)
        {
            return (crlanncontent)o;
        }

        if (o != null)
        {
            return new crlanncontent(asn1sequence.getinstance(o));
        }

        return null;
    }

    public crlanncontent(certificatelist crl)
    {
        this.content = new dersequence(crl);
    }

    public certificatelist[] getcertificatelists()
    {
        certificatelist[] result = new certificatelist[content.size()];

        for (int i = 0; i != result.length; i++)
        {
            result[i] = certificatelist.getinstance(content.getobjectat(i));
        }

        return result;
    }

    /**
     * <pre>
     * crlanncontent ::= sequence of certificatelist
     * </pre>
     * @return a basic asn.1 object representation.
     */
    public asn1primitive toasn1primitive()
    {
        return content;
    }
}
