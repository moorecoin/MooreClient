package org.ripple.bouncycastle.asn1.cmp;

import java.util.enumeration;

import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.derbitstring;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.dertaggedobject;

public class pkimessage
    extends asn1object
{
    private pkiheader header;
    private pkibody body;
    private derbitstring protection;
    private asn1sequence extracerts;

    private pkimessage(asn1sequence seq)
    {
        enumeration en = seq.getobjects();

        header = pkiheader.getinstance(en.nextelement());
        body = pkibody.getinstance(en.nextelement());

        while (en.hasmoreelements())
        {
            asn1taggedobject tobj = (asn1taggedobject)en.nextelement();

            if (tobj.gettagno() == 0)
            {
                protection = derbitstring.getinstance(tobj, true);
            }
            else
            {
                extracerts = asn1sequence.getinstance(tobj, true);
            }
        }
    }

    public static pkimessage getinstance(object o)
    {
        if (o instanceof pkimessage)
        {
            return (pkimessage)o;
        }
        else if (o != null)
        {
            return new pkimessage(asn1sequence.getinstance(o));
        }

        return null;
    }

    /**
     * creates a new pkimessage.
     *
     * @param header     message header
     * @param body       message body
     * @param protection message protection (may be null)
     * @param extracerts extra certificates (may be null)
     */
    public pkimessage(
        pkiheader header,
        pkibody body,
        derbitstring protection,
        cmpcertificate[] extracerts)
    {
        this.header = header;
        this.body = body;
        this.protection = protection;
        if (extracerts != null)
        {
            asn1encodablevector v = new asn1encodablevector();
            for (int i = 0; i < extracerts.length; i++)
            {
                v.add(extracerts[i]);
            }
            this.extracerts = new dersequence(v);
        }
    }

    public pkimessage(
        pkiheader header,
        pkibody body,
        derbitstring protection)
    {
        this(header, body, protection, null);
    }

    public pkimessage(
        pkiheader header,
        pkibody body)
    {
        this(header, body, null, null);
    }

    public pkiheader getheader()
    {
        return header;
    }

    public pkibody getbody()
    {
        return body;
    }

    public derbitstring getprotection()
    {
        return protection;
    }

    public cmpcertificate[] getextracerts()
    {
        if (extracerts == null)
        {
            return null;
        }

        cmpcertificate[] results = new cmpcertificate[extracerts.size()];

        for (int i = 0; i < results.length; i++)
        {
            results[i] = cmpcertificate.getinstance(extracerts.getobjectat(i));
        }
        return results;
    }

    /**
     * <pre>
     * pkimessage ::= sequence {
     *                  header           pkiheader,
     *                  body             pkibody,
     *                  protection   [0] pkiprotection optional,
     *                  extracerts   [1] sequence size (1..max) of cmpcertificate
     *                                                                     optional
     * }
     * </pre>
     *
     * @return a basic asn.1 object representation.
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector v = new asn1encodablevector();

        v.add(header);
        v.add(body);

        addoptional(v, 0, protection);
        addoptional(v, 1, extracerts);

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
