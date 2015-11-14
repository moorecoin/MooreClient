package org.ripple.bouncycastle.jce.provider;

import java.io.bufferedinputstream;
import java.io.ioexception;
import java.io.inputstream;
import java.security.cert.crl;
import java.security.cert.crlexception;
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
import org.ripple.bouncycastle.asn1.x509.certificatelist;
import org.ripple.bouncycastle.x509.x509streamparserspi;
import org.ripple.bouncycastle.x509.util.streamparsingexception;

public class x509crlparser
    extends x509streamparserspi
{
    private static final pemutil pem_parser = new pemutil("crl");

    private asn1set     sdata = null;
    private int         sdataobjectcount = 0;
    private inputstream currentstream = null;

    private crl readdercrl(
        inputstream in)
        throws ioexception, crlexception
    {
        asn1inputstream din = new asn1inputstream(in);
        asn1sequence seq = (asn1sequence)din.readobject();

        if (seq.size() > 1
                && seq.getobjectat(0) instanceof derobjectidentifier)
        {
            if (seq.getobjectat(0).equals(pkcsobjectidentifiers.signeddata))
            {
                sdata = new signeddata(asn1sequence.getinstance(
                                (asn1taggedobject)seq.getobjectat(1), true)).getcrls();

                return getcrl();
            }
        }

        return new x509crlobject(certificatelist.getinstance(seq));
    }

    private crl getcrl()
        throws crlexception
    {
        if (sdata == null || sdataobjectcount >= sdata.size())
        {
            return null;
        }

        return new x509crlobject(
                        certificatelist.getinstance(
                                sdata.getobjectat(sdataobjectcount++)));
    }

    private crl readpemcrl(
        inputstream  in)
        throws ioexception, crlexception
    {
        asn1sequence seq = pem_parser.readpemobject(in);

        if (seq != null)
        {
            return new x509crlobject(certificatelist.getinstance(seq));
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
                    return getcrl();
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
                return readpemcrl(currentstream);
            }
            else
            {
                currentstream.reset();
                return readdercrl(currentstream);
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
        crl     crl;
        list certs = new arraylist();

        while ((crl = (crl)engineread()) != null)
        {
            certs.add(crl);
        }

        return certs;
    }
}
