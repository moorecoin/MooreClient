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

public class keyrecrepcontent
    extends asn1object
{
    private pkistatusinfo status;
    private cmpcertificate newsigcert;
    private asn1sequence cacerts;
    private asn1sequence keypairhist;

    private keyrecrepcontent(asn1sequence seq)
    {
        enumeration en = seq.getobjects();

        status = pkistatusinfo.getinstance(en.nextelement());

        while (en.hasmoreelements())
        {
            asn1taggedobject tobj = asn1taggedobject.getinstance(en.nextelement());

            switch (tobj.gettagno())
            {
            case 0:
                newsigcert = cmpcertificate.getinstance(tobj.getobject());
                break;
            case 1:
                cacerts = asn1sequence.getinstance(tobj.getobject());
                break;
            case 2:
                keypairhist = asn1sequence.getinstance(tobj.getobject());
                break;
            default:
                throw new illegalargumentexception("unknown tag number: " + tobj.gettagno());
            }
        }
    }

    public static keyrecrepcontent getinstance(object o)
    {
        if (o instanceof keyrecrepcontent)
        {
            return (keyrecrepcontent)o;
        }

        if (o != null)
        {
            return new keyrecrepcontent(asn1sequence.getinstance(o));
        }

        return null;
    }


    public pkistatusinfo getstatus()
    {
        return status;
    }

    public cmpcertificate getnewsigcert()
    {
        return newsigcert;
    }

    public cmpcertificate[] getcacerts()
    {
        if (cacerts == null)
        {
            return null;
        }

        cmpcertificate[] results = new cmpcertificate[cacerts.size()];

        for (int i = 0; i != results.length; i++)
        {
            results[i] = cmpcertificate.getinstance(cacerts.getobjectat(i));
        }

        return results;
    }

    public certifiedkeypair[] getkeypairhist()
    {
        if (keypairhist == null)
        {
            return null;
        }

        certifiedkeypair[] results = new certifiedkeypair[keypairhist.size()];

        for (int i = 0; i != results.length; i++)
        {
            results[i] = certifiedkeypair.getinstance(keypairhist.getobjectat(i));
        }

        return results;
    }

    /**
     * <pre>
     * keyrecrepcontent ::= sequence {
     *                         status                  pkistatusinfo,
     *                         newsigcert          [0] cmpcertificate optional,
     *                         cacerts             [1] sequence size (1..max) of
     *                                                           cmpcertificate optional,
     *                         keypairhist         [2] sequence size (1..max) of
     *                                                           certifiedkeypair optional
     *              }
     * </pre> 
     * @return a basic asn.1 object representation.
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector v = new asn1encodablevector();

        v.add(status);

        addoptional(v, 0, newsigcert);
        addoptional(v, 1, cacerts);
        addoptional(v, 2, keypairhist);

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
