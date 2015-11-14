package org.ripple.bouncycastle.asn1.x509;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1utctime;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.dertaggedobject;
import org.ripple.bouncycastle.asn1.x500.x500name;

/**
 * generator for version 1 tbscertificatestructures.
 * <pre>
 * tbscertificate ::= sequence {
 *      version          [ 0 ]  version default v1(0),
 *      serialnumber            certificateserialnumber,
 *      signature               algorithmidentifier,
 *      issuer                  name,
 *      validity                validity,
 *      subject                 name,
 *      subjectpublickeyinfo    subjectpublickeyinfo,
 *      }
 * </pre>
 *
 */
public class v1tbscertificategenerator
{
    dertaggedobject         version = new dertaggedobject(true, 0, new asn1integer(0));

    asn1integer              serialnumber;
    algorithmidentifier     signature;
    x500name                issuer;
    time                    startdate, enddate;
    x500name                subject;
    subjectpublickeyinfo    subjectpublickeyinfo;

    public v1tbscertificategenerator()
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
        this.issuer = x500name.getinstance(issuer.toasn1primitive());
    }

    public void setissuer(
        x500name issuer)
    {
        this.issuer = issuer;
    }

    public void setstartdate(
        time startdate)
    {
        this.startdate = startdate;
    }

    public void setstartdate(
        asn1utctime startdate)
    {
        this.startdate = new time(startdate);
    }

    public void setenddate(
        time enddate)
    {
        this.enddate = enddate;
    }

    public void setenddate(
        asn1utctime enddate)
    {
        this.enddate = new time(enddate);
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

    public void setsubjectpublickeyinfo(
        subjectpublickeyinfo    pubkeyinfo)
    {
        this.subjectpublickeyinfo = pubkeyinfo;
    }

    public tbscertificate generatetbscertificate()
    {
        if ((serialnumber == null) || (signature == null)
            || (issuer == null) || (startdate == null) || (enddate == null)
            || (subject == null) || (subjectpublickeyinfo == null))
        {
            throw new illegalstateexception("not all mandatory fields set in v1 tbscertificate generator");
        }

        asn1encodablevector  seq = new asn1encodablevector();

        // seq.add(version); - not required as default value.
        seq.add(serialnumber);
        seq.add(signature);
        seq.add(issuer);

        //
        // before and after dates
        //
        asn1encodablevector  validity = new asn1encodablevector();

        validity.add(startdate);
        validity.add(enddate);

        seq.add(new dersequence(validity));

        seq.add(subject);

        seq.add(subjectpublickeyinfo);

        return tbscertificate.getinstance(new dersequence(seq));
    }
}
