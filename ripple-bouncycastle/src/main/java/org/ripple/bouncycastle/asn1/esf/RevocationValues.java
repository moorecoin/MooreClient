package org.ripple.bouncycastle.asn1.esf;

import java.util.enumeration;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.dertaggedobject;
import org.ripple.bouncycastle.asn1.ocsp.basicocspresponse;
import org.ripple.bouncycastle.asn1.x509.certificatelist;

/**
 * <pre>
 * revocationvalues ::= sequence {
 *    crlvals [0] sequence of certificatelist optional,
 *    ocspvals [1] sequence of basicocspresponse optional,
 *    otherrevvals [2] otherrevvals optional}
 * </pre>
 */
public class revocationvalues
    extends asn1object
{

    private asn1sequence crlvals;
    private asn1sequence ocspvals;
    private otherrevvals otherrevvals;

    public static revocationvalues getinstance(object obj)
    {
        if (obj instanceof revocationvalues)
        {
            return (revocationvalues)obj;
        }
        else if (obj != null)
        {
            return new revocationvalues(asn1sequence.getinstance(obj));
        }

        return null;
    }

    private revocationvalues(asn1sequence seq)
    {
        if (seq.size() > 3)
        {
            throw new illegalargumentexception("bad sequence size: "
                + seq.size());
        }
        enumeration e = seq.getobjects();
        while (e.hasmoreelements())
        {
            dertaggedobject o = (dertaggedobject)e.nextelement();
            switch (o.gettagno())
            {
                case 0:
                    asn1sequence crlvalsseq = (asn1sequence)o.getobject();
                    enumeration crlvalsenum = crlvalsseq.getobjects();
                    while (crlvalsenum.hasmoreelements())
                    {
                        certificatelist.getinstance(crlvalsenum.nextelement());
                    }
                    this.crlvals = crlvalsseq;
                    break;
                case 1:
                    asn1sequence ocspvalsseq = (asn1sequence)o.getobject();
                    enumeration ocspvalsenum = ocspvalsseq.getobjects();
                    while (ocspvalsenum.hasmoreelements())
                    {
                        basicocspresponse.getinstance(ocspvalsenum.nextelement());
                    }
                    this.ocspvals = ocspvalsseq;
                    break;
                case 2:
                    this.otherrevvals = otherrevvals.getinstance(o.getobject());
                    break;
                default:
                    throw new illegalargumentexception("invalid tag: "
                        + o.gettagno());
            }
        }
    }

    public revocationvalues(certificatelist[] crlvals,
                            basicocspresponse[] ocspvals, otherrevvals otherrevvals)
    {
        if (null != crlvals)
        {
            this.crlvals = new dersequence(crlvals);
        }
        if (null != ocspvals)
        {
            this.ocspvals = new dersequence(ocspvals);
        }
        this.otherrevvals = otherrevvals;
    }

    public certificatelist[] getcrlvals()
    {
        if (null == this.crlvals)
        {
            return new certificatelist[0];
        }
        certificatelist[] result = new certificatelist[this.crlvals.size()];
        for (int idx = 0; idx < result.length; idx++)
        {
            result[idx] = certificatelist.getinstance(this.crlvals
                .getobjectat(idx));
        }
        return result;
    }

    public basicocspresponse[] getocspvals()
    {
        if (null == this.ocspvals)
        {
            return new basicocspresponse[0];
        }
        basicocspresponse[] result = new basicocspresponse[this.ocspvals.size()];
        for (int idx = 0; idx < result.length; idx++)
        {
            result[idx] = basicocspresponse.getinstance(this.ocspvals
                .getobjectat(idx));
        }
        return result;
    }

    public otherrevvals getotherrevvals()
    {
        return this.otherrevvals;
    }

    public asn1primitive toasn1primitive()
    {
        asn1encodablevector v = new asn1encodablevector();
        if (null != this.crlvals)
        {
            v.add(new dertaggedobject(true, 0, this.crlvals));
        }
        if (null != this.ocspvals)
        {
            v.add(new dertaggedobject(true, 1, this.ocspvals));
        }
        if (null != this.otherrevvals)
        {
            v.add(new dertaggedobject(true, 2, this.otherrevvals.toasn1primitive()));
        }
        return new dersequence(v);
    }
}
