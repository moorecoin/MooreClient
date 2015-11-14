package org.ripple.bouncycastle.jcajce.provider.asymmetric.x509;

import java.io.ioexception;
import java.io.inputstream;
import java.io.pushbackinputstream;
import java.security.cert.crl;
import java.security.cert.crlexception;
import java.security.cert.certpath;
import java.security.cert.certificateexception;
import java.security.cert.certificatefactoryspi;
import java.security.cert.certificateparsingexception;
import java.security.cert.x509certificate;
import java.util.arraylist;
import java.util.collection;
import java.util.iterator;
import java.util.list;

import org.ripple.bouncycastle.asn1.asn1inputstream;
import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1set;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.pkcs.pkcsobjectidentifiers;
import org.ripple.bouncycastle.asn1.pkcs.signeddata;
import org.ripple.bouncycastle.asn1.x509.certificate;
import org.ripple.bouncycastle.asn1.x509.certificatelist;

/**
 * class for dealing with x509 certificates.
 * <p>
 * at the moment this will deal with "-----begin certificate-----" to "-----end certificate-----"
 * base 64 encoded certs, as well as the ber binaries of certificates and some classes of pkcs#7
 * objects.
 */
public class certificatefactory
    extends certificatefactoryspi
{
    private static final pemutil pem_cert_parser = new pemutil("certificate");
    private static final pemutil pem_crl_parser = new pemutil("crl");

    private asn1set sdata = null;
    private int                sdataobjectcount = 0;
    private inputstream currentstream = null;
    
    private asn1set scrldata = null;
    private int                scrldataobjectcount = 0;
    private inputstream currentcrlstream = null;

    private java.security.cert.certificate readdercertificate(
        asn1inputstream din)
        throws ioexception, certificateparsingexception
    {
        asn1sequence seq = (asn1sequence)din.readobject();

        if (seq.size() > 1
                && seq.getobjectat(0) instanceof asn1objectidentifier)
        {
            if (seq.getobjectat(0).equals(pkcsobjectidentifiers.signeddata))
            {
                sdata = signeddata.getinstance(asn1sequence.getinstance(
                    (asn1taggedobject)seq.getobjectat(1), true)).getcertificates();

                return getcertificate();
            }
        }

        return new x509certificateobject(
                            certificate.getinstance(seq));
    }

    private java.security.cert.certificate getcertificate()
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
                                    certificate.getinstance(obj));
                }
            }
        }

        return null;
    }

    private java.security.cert.certificate readpemcertificate(
        inputstream in)
        throws ioexception, certificateparsingexception
    {
        asn1sequence seq = pem_cert_parser.readpemobject(in);

        if (seq != null)
        {
            return new x509certificateobject(
                            certificate.getinstance(seq));
        }

        return null;
    }

    protected crl createcrl(certificatelist c)
    throws crlexception
    {
        return new x509crlobject(c);
    }
    
    private crl readpemcrl(
        inputstream in)
        throws ioexception, crlexception
    {
        asn1sequence seq = pem_crl_parser.readpemobject(in);

        if (seq != null)
        {
            return createcrl(
                            certificatelist.getinstance(seq));
        }

        return null;
    }

    private crl readdercrl(
        asn1inputstream ain)
        throws ioexception, crlexception
    {
        asn1sequence seq = (asn1sequence)ain.readobject();

        if (seq.size() > 1
                && seq.getobjectat(0) instanceof asn1objectidentifier)
        {
            if (seq.getobjectat(0).equals(pkcsobjectidentifiers.signeddata))
            {
                scrldata = signeddata.getinstance(asn1sequence.getinstance(
                    (asn1taggedobject)seq.getobjectat(1), true)).getcrls();
    
                return getcrl();
            }
        }

        return createcrl(
                     certificatelist.getinstance(seq));
    }

    private crl getcrl()
        throws crlexception
    {
        if (scrldata == null || scrldataobjectcount >= scrldata.size())
        {
            return null;
        }

        return createcrl(
                            certificatelist.getinstance(
                                scrldata.getobjectat(scrldataobjectcount++)));
    }

    /**
     * generates a certificate object and initializes it with the data
     * read from the input stream instream.
     */
    public java.security.cert.certificate enginegeneratecertificate(
        inputstream in)
        throws certificateexception
    {
        if (currentstream == null)
        {
            currentstream = in;
            sdata = null;
            sdataobjectcount = 0;
        }
        else if (currentstream != in) // reset if input stream has changed
        {
            currentstream = in;
            sdata = null;
            sdataobjectcount = 0;
        }

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

            pushbackinputstream pis = new pushbackinputstream(in);
            int tag = pis.read();

            if (tag == -1)
            {
                return null;
            }

            pis.unread(tag);

            if (tag != 0x30)  // assume ascii pem encoded.
            {
                return readpemcertificate(pis);
            }
            else
            {
                return readdercertificate(new asn1inputstream(pis));
            }
        }
        catch (exception e)
        {
            throw new excertificateexception(e);
        }
    }

    /**
     * returns a (possibly empty) collection view of the certificates
     * read from the given input stream instream.
     */
    public collection enginegeneratecertificates(
        inputstream instream)
        throws certificateexception
    {
        java.security.cert.certificate     cert;
        list certs = new arraylist();

        while ((cert = enginegeneratecertificate(instream)) != null)
        {
            certs.add(cert);
        }

        return certs;
    }

    /**
     * generates a certificate revocation list (crl) object and initializes
     * it with the data read from the input stream instream.
     */
    public crl enginegeneratecrl(
        inputstream instream)
        throws crlexception
    {
        if (currentcrlstream == null)
        {
            currentcrlstream = instream;
            scrldata = null;
            scrldataobjectcount = 0;
        }
        else if (currentcrlstream != instream) // reset if input stream has changed
        {
            currentcrlstream = instream;
            scrldata = null;
            scrldataobjectcount = 0;
        }

        try
        {
            if (scrldata != null)
            {
                if (scrldataobjectcount != scrldata.size())
                {
                    return getcrl();
                }
                else
                {
                    scrldata = null;
                    scrldataobjectcount = 0;
                    return null;
                }
            }

            pushbackinputstream pis = new pushbackinputstream(instream);
            int tag = pis.read();

            if (tag == -1)
            {
                return null;
            }

            pis.unread(tag);

            if (tag != 0x30)  // assume ascii pem encoded.
            {
                return readpemcrl(pis);
            }
            else
            {       // lazy evaluate to help processing of large crls
                return readdercrl(new asn1inputstream(pis, true));
            }
        }
        catch (crlexception e)
        {
            throw e;
        }
        catch (exception e)
        {
            throw new crlexception(e.tostring());
        }
    }

    /**
     * returns a (possibly empty) collection view of the crls read from
     * the given input stream instream.
     *
     * the instream may contain a sequence of der-encoded crls, or
     * a pkcs#7 crl set.  this is a pkcs#7 signeddata object, with the
     * only signficant field being crls.  in particular the signature
     * and the contents are ignored.
     */
    public collection enginegeneratecrls(
        inputstream instream)
        throws crlexception
    {
        crl crl;
        list crls = new arraylist();

        while ((crl = enginegeneratecrl(instream)) != null)
        {
            crls.add(crl);
        }

        return crls;
    }

    public iterator enginegetcertpathencodings()
    {
        return pkixcertpath.certpathencodings.iterator();
    }

    public certpath enginegeneratecertpath(
        inputstream instream)
        throws certificateexception
    {
        return enginegeneratecertpath(instream, "pkipath");
    }

    public certpath enginegeneratecertpath(
        inputstream instream,
        string encoding)
        throws certificateexception
    {
        return new pkixcertpath(instream, encoding);
    }

    public certpath enginegeneratecertpath(
        list certificates)
        throws certificateexception
    {
        iterator iter = certificates.iterator();
        object obj;
        while (iter.hasnext())
        {
            obj = iter.next();
            if (obj != null)
            {
                if (!(obj instanceof x509certificate))
                {
                    throw new certificateexception("list contains non x509certificate object while creating certpath\n" + obj.tostring());
                }
            }
        }
        return new pkixcertpath(certificates);
    }

    private class excertificateexception
        extends certificateexception
    {
        private throwable cause;

        public excertificateexception(throwable cause)
        {
            this.cause = cause;
        }

        public excertificateexception(string msg, throwable cause)
        {
            super(msg);

            this.cause = cause;
        }

        public throwable getcause()
        {
            return cause;
        }
    }
}
