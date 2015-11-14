package org.ripple.bouncycastle.asn1.crmf;

import java.util.enumeration;

import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.dersequence;

public class certreqmsg
    extends asn1object
{
    private certrequest certreq;
    private proofofpossession pop;
    private asn1sequence reginfo;

    private certreqmsg(asn1sequence seq)
    {
        enumeration en = seq.getobjects();

        certreq = certrequest.getinstance(en.nextelement());
        while (en.hasmoreelements())
        {
            object o = en.nextelement();

            if (o instanceof asn1taggedobject || o instanceof proofofpossession)
            {
                pop = proofofpossession.getinstance(o);
            }
            else
            {
                reginfo = asn1sequence.getinstance(o);
            }
        }
    }

    public static certreqmsg getinstance(object o)
    {
        if (o instanceof certreqmsg)
        {
            return (certreqmsg)o;
        }
        else if (o != null)
        {
            return new certreqmsg(asn1sequence.getinstance(o));
        }

        return null;
    }

    /**
     * creates a new certreqmsg.
     * @param certreq certrequest
     * @param pop may be null
     * @param reginfo may be null
     */
    public certreqmsg(
        certrequest certreq,
        proofofpossession pop,
        attributetypeandvalue[] reginfo)
    {
        if (certreq == null)
        {
            throw new illegalargumentexception("'certreq' cannot be null");
        }

        this.certreq = certreq;
        this.pop = pop;

        if (reginfo != null)
        {
            this.reginfo = new dersequence(reginfo);
        }
    }

    public certrequest getcertreq()
    {
        return certreq;
    }


    /**
     * @deprecated use getpopo
     */
    public proofofpossession getpop()
    {
        return pop;
    }


    public proofofpossession getpopo()
    {
        return pop;
    }

    public attributetypeandvalue[] getreginfo()
    {
        if (reginfo == null)
        {
            return null;
        }

        attributetypeandvalue[] results = new attributetypeandvalue[reginfo.size()];

        for (int i = 0; i != results.length; i++)
        {
            results[i] = attributetypeandvalue.getinstance(reginfo.getobjectat(i));
        }

        return results;
    }

    /**
     * <pre>
     * certreqmsg ::= sequence {
     *                    certreq   certrequest,
     *                    popo       proofofpossession  optional,
     *                    -- content depends upon key type
     *                    reginfo   sequence size(1..max) of attributetypeandvalue optional }
     * </pre>
     * @return a basic asn.1 object representation.
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector v = new asn1encodablevector();

        v.add(certreq);

        addoptional(v, pop);
        addoptional(v, reginfo);

        return new dersequence(v);
    }

    private void addoptional(asn1encodablevector v, asn1encodable obj)
    {
        if (obj != null)
        {
            v.add(obj);
        }
    }
}
