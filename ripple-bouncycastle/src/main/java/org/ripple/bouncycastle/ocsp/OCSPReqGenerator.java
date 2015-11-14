package org.ripple.bouncycastle.ocsp;

import java.io.bytearrayoutputstream;
import java.io.ioexception;
import java.security.generalsecurityexception;
import java.security.nosuchproviderexception;
import java.security.privatekey;
import java.security.securerandom;
import java.security.cert.certificateencodingexception;
import java.security.cert.x509certificate;
import java.util.arraylist;
import java.util.iterator;
import java.util.list;

import javax.security.auth.x500.x500principal;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1outputstream;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.derbitstring;
import org.ripple.bouncycastle.asn1.dernull;
import org.ripple.bouncycastle.asn1.derobjectidentifier;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.ocsp.ocsprequest;
import org.ripple.bouncycastle.asn1.ocsp.request;
import org.ripple.bouncycastle.asn1.ocsp.signature;
import org.ripple.bouncycastle.asn1.ocsp.tbsrequest;
import org.ripple.bouncycastle.asn1.x509.algorithmidentifier;
import org.ripple.bouncycastle.asn1.x509.extensions;
import org.ripple.bouncycastle.asn1.x509.generalname;
import org.ripple.bouncycastle.asn1.x509.x509certificatestructure;
import org.ripple.bouncycastle.asn1.x509.x509extensions;
import org.ripple.bouncycastle.jce.x509principal;

/**
 * @deprecated use classes in org.bouncycastle.cert.ocsp.
 */
public class ocspreqgenerator
{
    private list            list = new arraylist();
    private generalname     requestorname = null;
    private x509extensions  requestextensions = null;

    private class requestobject
    {
        certificateid   certid;
        x509extensions  extensions;

        public requestobject(
            certificateid   certid,
            x509extensions  extensions)
        {
            this.certid = certid;
            this.extensions = extensions;
        }

        public request torequest()
            throws exception
        {
            return new request(certid.toasn1object(), extensions.getinstance(extensions));
        }
    }

    /**
     * add a request for the given certificateid.
     * 
     * @param certid certificate id of interest
     */
    public void addrequest(
        certificateid   certid)
    {
        list.add(new requestobject(certid, null));
    }

    /**
     * add a request with extensions
     * 
     * @param certid certificate id of interest
     * @param singlerequestextensions the extensions to attach to the request
     */
    public void addrequest(
        certificateid   certid,
        x509extensions  singlerequestextensions)
    {
        list.add(new requestobject(certid, singlerequestextensions));
    }

    /**
     * set the requestor name to the passed in x500principal
     * 
     * @param requestorname a x500principal representing the requestor name.
     */
    public void setrequestorname(
        x500principal        requestorname)
    {
        try
        {
            this.requestorname = new generalname(generalname.directoryname, new x509principal(requestorname.getencoded()));
        }
        catch (ioexception e)
        {
            throw new illegalargumentexception("cannot encode principal: " + e);
        }
    }

    public void setrequestorname(
        generalname         requestorname)
    {
        this.requestorname = requestorname;
    }
    
    public void setrequestextensions(
        x509extensions      requestextensions)
    {
        this.requestextensions = requestextensions;
    }

    private ocspreq generaterequest(
        derobjectidentifier signingalgorithm,
        privatekey          key,
        x509certificate[]   chain,
        string              provider,
        securerandom        random)
        throws ocspexception, nosuchproviderexception
    {
        iterator    it = list.iterator();

        asn1encodablevector requests = new asn1encodablevector();

        while (it.hasnext())
        {
            try
            {
                requests.add(((requestobject)it.next()).torequest());
            }
            catch (exception e)
            {
                throw new ocspexception("exception creating request", e);
            }
        }

        tbsrequest  tbsreq = new tbsrequest(requestorname, new dersequence(requests), requestextensions);

        java.security.signature sig = null;
        signature               signature = null;

        if (signingalgorithm != null)
        {
            if (requestorname == null)
            {
                throw new ocspexception("requestorname must be specified if request is signed.");
            }
            
            try
            {
                sig = ocsputil.createsignatureinstance(signingalgorithm.getid(), provider);
                if (random != null)
                {
                    sig.initsign(key, random);
                }
                else
                {
                    sig.initsign(key);
                }
            }
            catch (nosuchproviderexception e)
            {
                // todo why this special case?
                throw e;
            }
            catch (generalsecurityexception e)
            {
                throw new ocspexception("exception creating signature: " + e, e);
            }

            derbitstring    bitsig = null;

            try
            {
                bytearrayoutputstream   bout = new bytearrayoutputstream();
                asn1outputstream        aout = new asn1outputstream(bout);

                aout.writeobject(tbsreq);

                sig.update(bout.tobytearray());

                bitsig = new derbitstring(sig.sign());
            }
            catch (exception e)
            {
                throw new ocspexception("exception processing tbsrequest: " + e, e);
            }

            algorithmidentifier sigalgid = new algorithmidentifier(signingalgorithm, dernull.instance);

            if (chain != null && chain.length > 0)
            {
                asn1encodablevector v = new asn1encodablevector();
                try
                {
                    for (int i = 0; i != chain.length; i++)
                    {
                        v.add(new x509certificatestructure(
                            (asn1sequence)asn1primitive.frombytearray(chain[i].getencoded())));
                    }
                }
                catch (ioexception e)
                {
                    throw new ocspexception("error processing certs", e);
                }
                catch (certificateencodingexception e)
                {
                    throw new ocspexception("error encoding certs", e);
                }

                signature = new signature(sigalgid, bitsig, new dersequence(v));
            }
            else
            {
                signature = new signature(sigalgid, bitsig);
            }
        }

        return new ocspreq(new ocsprequest(tbsreq, signature));
    }
    
    /**
     * generate an unsigned request
     * 
     * @return the ocspreq
     * @throws ocspexception
     */
    public ocspreq generate()
        throws ocspexception
    {
        try
        {
            return generaterequest(null, null, null, null, null);
        }
        catch (nosuchproviderexception e)
        {
            //
            // this shouldn't happen but...
            //
            throw new ocspexception("no provider! - " + e, e);
        }
    }

    public ocspreq generate(
        string              signingalgorithm,
        privatekey          key,
        x509certificate[]   chain,
        string              provider)
        throws ocspexception, nosuchproviderexception, illegalargumentexception
    {
        return generate(signingalgorithm, key, chain, provider, null);
    }

    public ocspreq generate(
        string              signingalgorithm,
        privatekey          key,
        x509certificate[]   chain,
        string              provider,
        securerandom        random)
        throws ocspexception, nosuchproviderexception, illegalargumentexception
    {
        if (signingalgorithm == null)
        {
            throw new illegalargumentexception("no signing algorithm specified");
        }

        try
        {
            derobjectidentifier oid = ocsputil.getalgorithmoid(signingalgorithm);
            
            return generaterequest(oid, key, chain, provider, random);
        }
        catch (illegalargumentexception e)
        {
            throw new illegalargumentexception("unknown signing algorithm specified: " + signingalgorithm);
        }
    }
    
    /**
     * return an iterator of the signature names supported by the generator.
     * 
     * @return an iterator containing recognised names.
     */
    public iterator getsignaturealgnames()
    {
        return ocsputil.getalgnames();
    }
}
