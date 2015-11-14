package org.ripple.bouncycastle.asn1.x509;

import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.derbitstring;
import org.ripple.bouncycastle.asn1.x500.x500name;

/**
 * an x509certificate structure.
 * <pre>
 *  certificate ::= sequence {
 *      tbscertificate          tbscertificate,
 *      signaturealgorithm      algorithmidentifier,
 *      signature               bit string
 *  }
 * </pre>
 */
public class certificate
    extends asn1object
{
    asn1sequence  seq;
    tbscertificate tbscert;
    algorithmidentifier     sigalgid;
    derbitstring            sig;

    public static certificate getinstance(
        asn1taggedobject obj,
        boolean          explicit)
    {
        return getinstance(asn1sequence.getinstance(obj, explicit));
    }

    public static certificate getinstance(
        object  obj)
    {
        if (obj instanceof certificate)
        {
            return (certificate)obj;
        }
        else if (obj != null)
        {
            return new certificate(asn1sequence.getinstance(obj));
        }

        return null;
    }

    private certificate(
        asn1sequence seq)
    {
        this.seq = seq;

        //
        // correct x509 certficate
        //
        if (seq.size() == 3)
        {
            tbscert = tbscertificate.getinstance(seq.getobjectat(0));
            sigalgid = algorithmidentifier.getinstance(seq.getobjectat(1));

            sig = derbitstring.getinstance(seq.getobjectat(2));
        }
        else
        {
            throw new illegalargumentexception("sequence wrong size for a certificate");
        }
    }

    public tbscertificate gettbscertificate()
    {
        return tbscert;
    }

    public asn1integer getversion()
    {
        return tbscert.getversion();
    }

    public int getversionnumber()
    {
        return tbscert.getversionnumber();
    }

    public asn1integer getserialnumber()
    {
        return tbscert.getserialnumber();
    }

    public x500name getissuer()
    {
        return tbscert.getissuer();
    }

    public time getstartdate()
    {
        return tbscert.getstartdate();
    }

    public time getenddate()
    {
        return tbscert.getenddate();
    }

    public x500name getsubject()
    {
        return tbscert.getsubject();
    }

    public subjectpublickeyinfo getsubjectpublickeyinfo()
    {
        return tbscert.getsubjectpublickeyinfo();
    }

    public algorithmidentifier getsignaturealgorithm()
    {
        return sigalgid;
    }

    public derbitstring getsignature()
    {
        return sig;
    }

    public asn1primitive toasn1primitive()
    {
        return seq;
    }
}
