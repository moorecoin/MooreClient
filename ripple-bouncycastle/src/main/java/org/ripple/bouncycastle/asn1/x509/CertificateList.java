
package org.ripple.bouncycastle.asn1.x509;

import java.util.enumeration;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.derbitstring;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.x500.x500name;

/**
 * pkix rfc-2459
 *
 * the x.509 v2 crl syntax is as follows.  for signature calculation,
 * the data that is to be signed is asn.1 der encoded.
 *
 * <pre>
 * certificatelist  ::=  sequence  {
 *      tbscertlist          tbscertlist,
 *      signaturealgorithm   algorithmidentifier,
 *      signaturevalue       bit string  }
 * </pre>
 */
public class certificatelist
    extends asn1object
{
    tbscertlist            tbscertlist;
    algorithmidentifier    sigalgid;
    derbitstring           sig;

    public static certificatelist getinstance(
        asn1taggedobject obj,
        boolean          explicit)
    {
        return getinstance(asn1sequence.getinstance(obj, explicit));
    }

    public static certificatelist getinstance(
        object  obj)
    {
        if (obj instanceof certificatelist)
        {
            return (certificatelist)obj;
        }
        else if (obj != null)
        {
            return new certificatelist(asn1sequence.getinstance(obj));
        }

        return null;
    }

    public certificatelist(
        asn1sequence seq)
    {
        if (seq.size() == 3)
        {
            tbscertlist = tbscertlist.getinstance(seq.getobjectat(0));
            sigalgid = algorithmidentifier.getinstance(seq.getobjectat(1));
            sig = derbitstring.getinstance(seq.getobjectat(2));
        }
        else
        {
            throw new illegalargumentexception("sequence wrong size for certificatelist");
        }
    }

    public tbscertlist gettbscertlist()
    {
        return tbscertlist;
    }

    public tbscertlist.crlentry[] getrevokedcertificates()
    {
        return tbscertlist.getrevokedcertificates();
    }

    public enumeration getrevokedcertificateenumeration()
    {
        return tbscertlist.getrevokedcertificateenumeration();
    }

    public algorithmidentifier getsignaturealgorithm()
    {
        return sigalgid;
    }

    public derbitstring getsignature()
    {
        return sig;
    }

    public int getversionnumber()
    {
        return tbscertlist.getversionnumber();
    }

    public x500name getissuer()
    {
        return tbscertlist.getissuer();
    }

    public time getthisupdate()
    {
        return tbscertlist.getthisupdate();
    }

    public time getnextupdate()
    {
        return tbscertlist.getnextupdate();
    }

    public asn1primitive toasn1primitive()
    {
        asn1encodablevector v = new asn1encodablevector();

        v.add(tbscertlist);
        v.add(sigalgid);
        v.add(sig);

        return new dersequence(v);
    }
}
