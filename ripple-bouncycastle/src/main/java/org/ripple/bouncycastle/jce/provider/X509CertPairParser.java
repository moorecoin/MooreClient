package org.ripple.bouncycastle.jce.provider;

import java.io.bufferedinputstream;
import java.io.ioexception;
import java.io.inputstream;
import java.security.cert.certificateparsingexception;
import java.util.arraylist;
import java.util.collection;
import java.util.list;

import org.ripple.bouncycastle.asn1.asn1inputstream;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.x509.certificatepair;
import org.ripple.bouncycastle.x509.x509certificatepair;
import org.ripple.bouncycastle.x509.x509streamparserspi;
import org.ripple.bouncycastle.x509.util.streamparsingexception;

public class x509certpairparser
    extends x509streamparserspi
{
    private inputstream currentstream = null;

    private x509certificatepair readdercrosscertificatepair(
        inputstream in)
        throws ioexception, certificateparsingexception
    {
        asn1inputstream din = new asn1inputstream(in);
        asn1sequence seq = (asn1sequence)din.readobject();
        certificatepair pair = certificatepair.getinstance(seq);
        return new x509certificatepair(pair);
    }

    public void engineinit(inputstream in)
    {
        currentstream = in;

        if (!currentstream.marksupported())
        {
            currentstream = new bufferedinputstream(currentstream);
        }
    }

    public object engineread() throws streamparsingexception
    {
        try
        {

            currentstream.mark(10);
            int tag = currentstream.read();

            if (tag == -1)
            {
                return null;
            }

            currentstream.reset();
            return readdercrosscertificatepair(currentstream);
        }
        catch (exception e)
        {
            throw new streamparsingexception(e.tostring(), e);
        }
    }

    public collection enginereadall() throws streamparsingexception
    {
        x509certificatepair pair;
        list certs = new arraylist();

        while ((pair = (x509certificatepair)engineread()) != null)
        {
            certs.add(pair);
        }

        return certs;
    }
}
