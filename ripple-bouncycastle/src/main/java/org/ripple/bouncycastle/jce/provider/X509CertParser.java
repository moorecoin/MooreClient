package org.ripple.bouncycastle.jce.provider;

import java.io.bufferedinputstream;
import java.io.ioexception;
import java.io.inputstream;
import java.security.cert.certificate;
import java.security.cert.certificateparsingexception;
import java.util.arraylist;
import java.util.collection;
import java.util.list;

import org.ripple.bouncycastle.asn1.asn1inputstream;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1set;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.derobjectidentifier;
import org.ripple.bouncycastle.asn1.pkcs.pkcsobjectidentifiers;
import org.ripple.bouncycastle.asn1.pkcs.signeddata;
import org.ripple.bouncycastle.x509.x509streamparserspi;
import org.ripple.bouncycastle.x509.util.streamparsingexception;

public class x509certparser
    extends x509streamparserspi
{
    private static final pemutil pem_parser = new pemutil("certificate");

    private asn1set     sdata = null;
    private int         sdataobjectcount = 0;
    private inputstream currentstream = null;

    private certificate readdercertificate(
        inputstream in)
        throws ioexception, certificateparsingexception
    {
        asn1inputstream din = new asn1inputstream(in);
        asn1sequence seq = (asn1sequence)din.readobject();

        if (seq.size() > 1
                && seq.getobjectat(0) instanceof derobjectidentifier)
        {
            if (seq.getobjectat(0).equals(pkcsobjectidentifiers.signeddata))
            {
                sdata = new signeddata(asn1sequence.getinstance(
                                (asn1taggedobject)seq.getobjectat(1), true)).getcertificates();

                return getcertificate();
            }
        }

        return new x509certificateobject(
                            org.ripple.bouncycastle.asn1.x509.certificate.getinstance(seq));
    }

    private certificate getcertificate()
        throws certificateparsingexception
    {
        if (sdata != null)
        {
            while (sdataobjectcount < sdata.size())
            {
                object obj = sdata.getobjectat(sdataobjectcount++);

                if (obj instanceof asn1sequence)
                {
                   return new x509certificateobject(
                                    org.ripple.bouncycastle.asn1.x509.certificate.getinstance(obj));
                }
            }
        }

        return null;
    }

    private certificate readpemcertificate(
        inputstream  in)
        throws ioexception, certificateparsingexception
    {
        asn1sequence seq = pem_parser.readpemobject(in);

        if (seq != null)
        {
            return new x509certificateobject(
                            org.ripple.bouncycastle.asn1.x509.certificate.getinstance(seq));
        }

        return null;
    }

    public void engineinit(inputstream in)
    {
        currentstream = in;
        sdata = null;
        sdataobjectcount = 0;

        if (!currentstream.marksupported())
        {
            currentstream = new bufferedinputstream(currentstream);
        }
    }

    public object engineread()
        throws streamparsingexception
    {
        try
        {
            if (sdata != null)
            {
                if (sdataobjectcount != sdata.size())
                {
                    return getcertificate();
                }
                else
                {
                    sdata = null;
                    sdataobjectcount = 0;
                    return null;
                }
            }

            currentstream.mark(10);
            int    tag = currentstream.read();

            if (tag == -1)
            {
                return null;
            }

            if (tag != 0x30)  // assume ascii pem encoded.
            {
                currentstream.reset();
                return readpemcertificate(currentstream);
            }
            else
            {
                currentstream.reset();
                return readdercertificate(currentstream);
            }
        }
        catch (exception e)
        {
            throw new streamparsingexception(e.tostring(), e);
        }
    }

    public collection enginereadall()
        throws streamparsingexception
    {
        certificate     cert;
        list certs = new arraylist();

        while ((cert = (certificate)engineread()) != null)
        {
            certs.add(cert);
        }

        return certs;
    }
}
