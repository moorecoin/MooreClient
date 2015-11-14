package org.ripple.bouncycastle.asn1.cmp;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.dertaggedobject;
import org.ripple.bouncycastle.asn1.crmf.certid;
import org.ripple.bouncycastle.asn1.x509.certificatelist;

public class revrepcontentbuilder
{
    private asn1encodablevector status = new asn1encodablevector();
    private asn1encodablevector revcerts = new asn1encodablevector();
    private asn1encodablevector crls = new asn1encodablevector();

    public revrepcontentbuilder add(pkistatusinfo status)
    {
        this.status.add(status);

        return this;
    }

    public revrepcontentbuilder add(pkistatusinfo status, certid certid)
    {
        if (this.status.size() != this.revcerts.size())
        {
            throw new illegalstateexception("status and revcerts sequence must be in common order");
        }
        this.status.add(status);
        this.revcerts.add(certid);

        return this;
    }

    public revrepcontentbuilder addcrl(certificatelist crl)
    {
        this.crls.add(crl);

        return this;
    }

    public revrepcontent build()
    {
        asn1encodablevector v = new asn1encodablevector();

        v.add(new dersequence(status));

        if (revcerts.size() != 0)
        {
            v.add(new dertaggedobject(true, 0, new dersequence(revcerts)));
        }

        if (crls.size() != 0)
        {
            v.add(new dertaggedobject(true, 1, new dersequence(crls)));
        }

        return revrepcontent.getinstance(new dersequence(v));
    }
}
