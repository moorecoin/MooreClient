package org.ripple.bouncycastle.asn1.cmp;

import java.util.enumeration;

import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.dertaggedobject;
import org.ripple.bouncycastle.asn1.crmf.certid;
import org.ripple.bouncycastle.asn1.x509.certificatelist;

public class revrepcontent
    extends asn1object
{
    private asn1sequence status;
    private asn1sequence revcerts;
    private asn1sequence crls;

    private revrepcontent(asn1sequence seq)
    {
        enumeration en = seq.getobjects();

        status = asn1sequence.getinstance(en.nextelement());
        while (en.hasmoreelements())
        {
            asn1taggedobject tobj = asn1taggedobject.getinstance(en.nextelement());

            if (tobj.gettagno() == 0)
            {
                revcerts = asn1sequence.getinstance(tobj, true);
            }
            else
            {
                crls = asn1sequence.getinstance(tobj, true);
            }
        }
    }

    public static revrepcontent getinstance(object o)
    {
        if (o instanceof revrepcontent)
        {
            return (revrepcontent)o;
        }

        if (o != null)
        {
            return new revrepcontent(asn1sequence.getinstance(o));
        }

        return null;
    }

    public pkistatusinfo[] getstatus()
    {
        pkistatusinfo[] results = new pkistatusinfo[status.size()];

        for (int i = 0; i != results.length; i++)
        {
            results[i] = pkistatusinfo.getinstance(status.getobjectat(i));
        }

        return results;
    }

    public certid[] getrevcerts()
    {
        if (revcerts == null)
        {
            return null;
        }

        certid[] results = new certid[revcerts.size()];

        for (int i = 0; i != results.length; i++)
        {
            results[i] = certid.getinstance(revcerts.getobjectat(i));
        }

        return results;
    }

    public certificatelist[] getcrls()
    {
        if (crls == null)
        {
            return null;
        }

        certificatelist[] results = new certificatelist[crls.size()];

        for (int i = 0; i != results.length; i++)
        {
            results[i] = certificatelist.getinstance(crls.getobjectat(i));
        }

        return results;
    }

    /**
     * <pre>
     * revrepcontent ::= sequence {
     *        status       sequence size (1..max) of pkistatusinfo,
     *        -- in same order as was sent in revreqcontent
     *        revcerts [0] sequence size (1..max) of certid optional,
     *        -- ids for which revocation was requested
     *        -- (same order as status)
     *        crls     [1] sequence size (1..max) of certificatelist optional
     *        -- the resulting crls (there may be more than one)
     *   }
     * </pre>
     * @return a basic asn.1 object representation.
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector v = new asn1encodablevector();

        v.add(status);

        addoptional(v, 0, revcerts);
        addoptional(v, 1, crls);

        return new dersequence(v);
    }

    private void addoptional(asn1encodablevector v, int tagno, asn1encodable obj)
    {
        if (obj != null)
        {
            v.add(new dertaggedobject(true, tagno, obj));
        }
    }
}
