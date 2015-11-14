package org.ripple.bouncycastle.asn1.x509;

import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.derbitstring;
import org.ripple.bouncycastle.asn1.pkcs.pkcsobjectidentifiers;
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
 * @deprecated use org.bouncycastle.asn1.x509.certificate
 */
public class x509certificatestructure
    extends asn1object
    implements x509objectidentifiers, pkcsobjectidentifiers
{
    asn1sequence  seq;
    tbscertificatestructure tbscert;
    algorithmidentifier     sigalgid;
    derbitstring            sig;

    public static x509certificatestructure getinstance(
        asn1taggedobject obj,
        boolean          explicit)
    {
        return getinstance(asn1sequence.getinstance(obj, explicit));
    }

    public static x509certificatestructure getinstance(
        object  obj)
    {
        if (obj instanceof x509certificatestructure)
        {
            return (x509certificatestructure)obj;
        }
        else if (obj != null)
        {
            return new x509certificatestructure(asn1sequence.getinstance(obj));
        }

        return null;
    }

    public x509certificatestructure(
        asn1sequence  seq)
    {
        this.seq = seq;

        //
        // correct x509 certficate
        //
        if (seq.size() == 3)
        {
            tbscert = tbscertificatestructure.getinstance(seq.getobjectat(0));
            sigalgid = algorithmidentifier.getinstance(seq.getobjectat(1));

            sig = derbitstring.getinstance(seq.getobjectat(2));
        }
        else
        {
            throw new illegalargumentexception("sequence wrong size for a certificate");
        }
    }

    public tbscertificatestructure gettbscertificate()
    {
        return tbscert;
    }

    public int getversion()
    {
        return tbscert.getversion();
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
