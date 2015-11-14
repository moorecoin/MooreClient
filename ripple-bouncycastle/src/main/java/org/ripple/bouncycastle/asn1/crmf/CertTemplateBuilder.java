package org.ripple.bouncycastle.asn1.crmf;

import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.derbitstring;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.dertaggedobject;
import org.ripple.bouncycastle.asn1.x500.x500name;
import org.ripple.bouncycastle.asn1.x509.algorithmidentifier;
import org.ripple.bouncycastle.asn1.x509.extensions;
import org.ripple.bouncycastle.asn1.x509.subjectpublickeyinfo;
import org.ripple.bouncycastle.asn1.x509.x509extensions;

public class certtemplatebuilder
{
    private asn1integer version;
    private asn1integer serialnumber;
    private algorithmidentifier signingalg;
    private x500name issuer;
    private optionalvalidity validity;
    private x500name subject;
    private subjectpublickeyinfo publickey;
    private derbitstring issueruid;
    private derbitstring subjectuid;
    private extensions extensions;

    /** sets the x.509 version. note: for x509v3, use 2 here. */
    public certtemplatebuilder setversion(int ver)
    {
        version = new asn1integer(ver);

        return this;
    }

    public certtemplatebuilder setserialnumber(asn1integer ser)
    {
        serialnumber = ser;

        return this;
    }

    public certtemplatebuilder setsigningalg(algorithmidentifier aid)
    {
        signingalg = aid;

        return this;
    }

    public certtemplatebuilder setissuer(x500name name)
    {
        issuer = name;

        return this;
    }

    public certtemplatebuilder setvalidity(optionalvalidity v)
    {
        validity = v;

        return this;
    }

    public certtemplatebuilder setsubject(x500name name)
    {
        subject = name;

        return this;
    }

    public certtemplatebuilder setpublickey(subjectpublickeyinfo spki)
    {
        publickey = spki;

        return this;
    }

    /** sets the issuer unique id (deprecated in x.509v3) */
    public certtemplatebuilder setissueruid(derbitstring uid)
    {
        issueruid = uid;

        return this;
    }

    /** sets the subject unique id (deprecated in x.509v3) */
    public certtemplatebuilder setsubjectuid(derbitstring uid)
    {
        subjectuid = uid;

        return this;
    }

    /**
     * @deprecated use method taking extensions
     * @param extens
     * @return
     */
    public certtemplatebuilder setextensions(x509extensions extens)
    {
        return setextensions(extensions.getinstance(extens));
    }

    public certtemplatebuilder setextensions(extensions extens)
    {
        extensions = extens;

        return this;
    }

    /**
     * <pre>
     *  certtemplate ::= sequence {
     *      version      [0] version               optional,
     *      serialnumber [1] integer               optional,
     *      signingalg   [2] algorithmidentifier   optional,
     *      issuer       [3] name                  optional,
     *      validity     [4] optionalvalidity      optional,
     *      subject      [5] name                  optional,
     *      publickey    [6] subjectpublickeyinfo  optional,
     *      issueruid    [7] uniqueidentifier      optional,
     *      subjectuid   [8] uniqueidentifier      optional,
     *      extensions   [9] extensions            optional }
     * </pre>
     * @return a basic asn.1 object representation.
     */
    public certtemplate build()
    {
        asn1encodablevector v = new asn1encodablevector();

        addoptional(v, 0, false, version);
        addoptional(v, 1, false, serialnumber);
        addoptional(v, 2, false, signingalg);
        addoptional(v, 3, true, issuer); // choice
        addoptional(v, 4, false, validity);
        addoptional(v, 5, true, subject); // choice
        addoptional(v, 6, false, publickey);
        addoptional(v, 7, false, issueruid);
        addoptional(v, 8, false, subjectuid);
        addoptional(v, 9, false, extensions);

        return certtemplate.getinstance(new dersequence(v));
    }

    private void addoptional(asn1encodablevector v, int tagno, boolean isexplicit, asn1encodable obj)
    {
        if (obj != null)
        {
            v.add(new dertaggedobject(isexplicit, tagno, obj));
        }
    }
}
