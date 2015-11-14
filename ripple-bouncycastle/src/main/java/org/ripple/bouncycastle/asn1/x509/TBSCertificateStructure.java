package org.ripple.bouncycastle.asn1.x509;

import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.derbitstring;
import org.ripple.bouncycastle.asn1.dertaggedobject;
import org.ripple.bouncycastle.asn1.pkcs.pkcsobjectidentifiers;
import org.ripple.bouncycastle.asn1.x500.x500name;

/**
 * the tbscertificate object.
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
 * <p>
 * note: issueruniqueid and subjectuniqueid are both deprecated by the ietf. this class
 * will parse them, but you really shouldn't be creating new ones.
 */
public class tbscertificatestructure
    extends asn1object
    implements x509objectidentifiers, pkcsobjectidentifiers
{
    asn1sequence            seq;

    asn1integer             version;
    asn1integer             serialnumber;
    algorithmidentifier     signature;
    x500name                issuer;
    time                    startdate, enddate;
    x500name                subject;
    subjectpublickeyinfo    subjectpublickeyinfo;
    derbitstring            issueruniqueid;
    derbitstring            subjectuniqueid;
    x509extensions          extensions;

    public static tbscertificatestructure getinstance(
        asn1taggedobject obj,
        boolean          explicit)
    {
        return getinstance(asn1sequence.getinstance(obj, explicit));
    }

    public static tbscertificatestructure getinstance(
        object  obj)
    {
        if (obj instanceof tbscertificatestructure)
        {
            return (tbscertificatestructure)obj;
        }
        else if (obj != null)
        {
            return new tbscertificatestructure(asn1sequence.getinstance(obj));
        }

        return null;
    }

    public tbscertificatestructure(
        asn1sequence  seq)
    {
        int         seqstart = 0;

        this.seq = seq;

        //
        // some certficates don't include a version number - we assume v1
        //
        if (seq.getobjectat(0) instanceof dertaggedobject)
        {
            version = asn1integer.getinstance((asn1taggedobject)seq.getobjectat(0), true);
        }
        else
        {
            seqstart = -1;          // field 0 is missing!
            version = new asn1integer(0);
        }

        serialnumber = asn1integer.getinstance(seq.getobjectat(seqstart + 1));

        signature = algorithmidentifier.getinstance(seq.getobjectat(seqstart + 2));
        issuer = x500name.getinstance(seq.getobjectat(seqstart + 3));

        //
        // before and after dates
        //
        asn1sequence  dates = (asn1sequence)seq.getobjectat(seqstart + 4);

        startdate = time.getinstance(dates.getobjectat(0));
        enddate = time.getinstance(dates.getobjectat(1));

        subject = x500name.getinstance(seq.getobjectat(seqstart + 5));

        //
        // public key info.
        //
        subjectpublickeyinfo = subjectpublickeyinfo.getinstance(seq.getobjectat(seqstart + 6));

        for (int extras = seq.size() - (seqstart + 6) - 1; extras > 0; extras--)
        {
            dertaggedobject extra = (dertaggedobject)seq.getobjectat(seqstart + 6 + extras);

            switch (extra.gettagno())
            {
            case 1:
                issueruniqueid = derbitstring.getinstance(extra, false);
                break;
            case 2:
                subjectuniqueid = derbitstring.getinstance(extra, false);
                break;
            case 3:
                extensions = x509extensions.getinstance(extra);
            }
        }
    }

    public int getversion()
    {
        return version.getvalue().intvalue() + 1;
    }

    public asn1integer getversionnumber()
    {
        return version;
    }

    public asn1integer getserialnumber()
    {
        return serialnumber;
    }

    public algorithmidentifier getsignature()
    {
        return signature;
    }

    public x500name getissuer()
    {
        return issuer;
    }

    public time getstartdate()
    {
        return startdate;
    }

    public time getenddate()
    {
        return enddate;
    }

    public x500name getsubject()
    {
        return subject;
    }

    public subjectpublickeyinfo getsubjectpublickeyinfo()
    {
        return subjectpublickeyinfo;
    }

    public derbitstring getissueruniqueid()
    {
        return issueruniqueid;
    }

    public derbitstring getsubjectuniqueid()
    {
        return subjectuniqueid;
    }

    public x509extensions getextensions()
    {
        return extensions;
    }

    public asn1primitive toasn1primitive()
    {
        return seq;
    }
}
