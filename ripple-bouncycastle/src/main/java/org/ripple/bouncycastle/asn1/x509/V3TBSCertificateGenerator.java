package org.ripple.bouncycastle.asn1.x509;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.derbitstring;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.dertaggedobject;
import org.ripple.bouncycastle.asn1.derutctime;
import org.ripple.bouncycastle.asn1.x500.x500name;

/**
 * generator for version 3 tbscertificatestructures.
 * <pre>
 * tbscertificate ::= sequence {
 *      version          [ 0 ]  version default v1(0),
 *      serialnumber            certificateserialnumber,
 *      signature               algorithmidentifier,
 *      issuer                  name,
 *      validity                validity,
 *      subject                 name,
 *      subjectpublickeyinfo    subjectpublickeyinfo,
 *      issueruniqueid    [ 1 ] implicit uniqueidentifier optional,
 *      subjectuniqueid   [ 2 ] implicit uniqueidentifier optional,
 *      extensions        [ 3 ] extensions optional
 *      }
 * </pre>
 *
 */
public class v3tbscertificategenerator
{
    dertaggedobject         version = new dertaggedobject(true, 0, new asn1integer(2));

    asn1integer              serialnumber;
    algorithmidentifier     signature;
    x500name                issuer;
    time                    startdate, enddate;
    x500name                subject;
    subjectpublickeyinfo    subjectpublickeyinfo;
    extensions              extensions;

    private boolean altnamepresentandcritical;
    private derbitstring issueruniqueid;
    private derbitstring subjectuniqueid;

    public v3tbscertificategenerator()
    {
    }

    public void setserialnumber(
        asn1integer  serialnumber)
    {
        this.serialnumber = serialnumber;
    }

    public void setsignature(
        algorithmidentifier    signature)
    {
        this.signature = signature;
    }

        /**
     * @deprecated use x500name method
     */
    public void setissuer(
        x509name    issuer)
    {
        this.issuer = x500name.getinstance(issuer);
    }

    public void setissuer(
        x500name issuer)
    {
        this.issuer = issuer;
    }
    
    public void setstartdate(
        derutctime startdate)
    {
        this.startdate = new time(startdate);
    }

    public void setstartdate(
        time startdate)
    {
        this.startdate = startdate;
    }

    public void setenddate(
        derutctime enddate)
    {
        this.enddate = new time(enddate);
    }

    public void setenddate(
        time enddate)
    {
        this.enddate = enddate;
    }

        /**
     * @deprecated use x500name method
     */
    public void setsubject(
        x509name    subject)
    {
        this.subject = x500name.getinstance(subject.toasn1primitive());
    }

    public void setsubject(
        x500name subject)
    {
        this.subject = subject;
    }

    public void setissueruniqueid(
        derbitstring uniqueid)
    {
        this.issueruniqueid = uniqueid;
    }

    public void setsubjectuniqueid(
        derbitstring uniqueid)
    {
        this.subjectuniqueid = uniqueid;
    }

    public void setsubjectpublickeyinfo(
        subjectpublickeyinfo    pubkeyinfo)
    {
        this.subjectpublickeyinfo = pubkeyinfo;
    }

    /**
     * @deprecated use method taking extensions
     * @param extensions
     */
    public void setextensions(
        x509extensions    extensions)
    {
        setextensions(extensions.getinstance(extensions));
    }

    public void setextensions(
        extensions    extensions)
    {
        this.extensions = extensions;
        if (extensions != null)
        {
            extension altname = extensions.getextension(extension.subjectalternativename);

            if (altname != null && altname.iscritical())
            {
                altnamepresentandcritical = true;
            }
        }
    }

    public tbscertificate generatetbscertificate()
    {
        if ((serialnumber == null) || (signature == null)
            || (issuer == null) || (startdate == null) || (enddate == null)
            || (subject == null && !altnamepresentandcritical) || (subjectpublickeyinfo == null))
        {
            throw new illegalstateexception("not all mandatory fields set in v3 tbscertificate generator");
        }

        asn1encodablevector  v = new asn1encodablevector();

        v.add(version);
        v.add(serialnumber);
        v.add(signature);
        v.add(issuer);

        //
        // before and after dates
        //
        asn1encodablevector  validity = new asn1encodablevector();

        validity.add(startdate);
        validity.add(enddate);

        v.add(new dersequence(validity));

        if (subject != null)
        {
            v.add(subject);
        }
        else
        {
            v.add(new dersequence());
        }

        v.add(subjectpublickeyinfo);

        if (issueruniqueid != null)
        {
            v.add(new dertaggedobject(false, 1, issueruniqueid));
        }

        if (subjectuniqueid != null)
        {
            v.add(new dertaggedobject(false, 2, subjectuniqueid));
        }

        if (extensions != null)
        {
            v.add(new dertaggedobject(true, 3, extensions));
        }

        return tbscertificate.getinstance(new dersequence(v));
    }
}
