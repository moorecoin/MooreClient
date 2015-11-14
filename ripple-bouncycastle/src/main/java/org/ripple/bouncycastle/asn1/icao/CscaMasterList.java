package org.ripple.bouncycastle.asn1.icao;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1set;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.derset;
import org.ripple.bouncycastle.asn1.x509.certificate;

/**
 * the cscamasterlist object. this object can be wrapped in a
 * cmssigneddata to be published in ldap.
 * <p/>
 * <pre>
 * cscamasterlist ::= sequence {
 *   version                cscamasterlistversion,
 *   certlist               set of certificate }
 *
 * cscamasterlistversion :: integer {v0(0)}
 * </pre>
 */

public class cscamasterlist
    extends asn1object
{
    private asn1integer version = new asn1integer(0);
    private certificate[] certlist;

    public static cscamasterlist getinstance(
        object obj)
    {
        if (obj instanceof cscamasterlist)
        {
            return (cscamasterlist)obj;
        }
        else if (obj != null)
        {
            return new cscamasterlist(asn1sequence.getinstance(obj));
        }

        return null;
    }

    private cscamasterlist(
        asn1sequence seq)
    {
        if (seq == null || seq.size() == 0)
        {
            throw new illegalargumentexception(
                "null or empty sequence passed.");
        }
        if (seq.size() != 2)
        {
            throw new illegalargumentexception(
                "incorrect sequence size: " + seq.size());
        }

        version = asn1integer.getinstance(seq.getobjectat(0));
        asn1set certset = asn1set.getinstance(seq.getobjectat(1));
        certlist = new certificate[certset.size()];
        for (int i = 0; i < certlist.length; i++)
        {
            certlist[i]
                = certificate.getinstance(certset.getobjectat(i));
        }
    }

    public cscamasterlist(
        certificate[] certstructs)
    {
        certlist = copycertlist(certstructs);
    }

    public int getversion()
    {
        return version.getvalue().intvalue();
    }

    public certificate[] getcertstructs()
    {
        return copycertlist(certlist);
    }

    private certificate[] copycertlist(certificate[] orig)
    {
        certificate[] certs = new certificate[orig.length];

        for (int i = 0; i != certs.length; i++)
        {
            certs[i] = orig[i];
        }

        return certs;
    }

    public asn1primitive toasn1primitive()
    {
        asn1encodablevector seq = new asn1encodablevector();

        seq.add(version);

        asn1encodablevector certset = new asn1encodablevector();
        for (int i = 0; i < certlist.length; i++)
        {
            certset.add(certlist[i]);
        }
        seq.add(new derset(certset));

        return new dersequence(seq);
    }
}
