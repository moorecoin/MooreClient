package org.ripple.bouncycastle.ocsp;

import java.io.ioexception;
import java.security.generalsecurityexception;
import java.security.nosuchproviderexception;
import java.security.privatekey;
import java.security.publickey;
import java.security.securerandom;
import java.security.signature;
import java.security.cert.certificateencodingexception;
import java.security.cert.x509certificate;
import java.util.arraylist;
import java.util.date;
import java.util.iterator;
import java.util.list;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1encoding;
import org.ripple.bouncycastle.asn1.asn1generalizedtime;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.derbitstring;
import org.ripple.bouncycastle.asn1.dergeneralizedtime;
import org.ripple.bouncycastle.asn1.dernull;
import org.ripple.bouncycastle.asn1.derobjectidentifier;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.ocsp.basicocspresponse;
import org.ripple.bouncycastle.asn1.ocsp.certstatus;
import org.ripple.bouncycastle.asn1.ocsp.responsedata;
import org.ripple.bouncycastle.asn1.ocsp.revokedinfo;
import org.ripple.bouncycastle.asn1.ocsp.singleresponse;
import org.ripple.bouncycastle.asn1.x509.algorithmidentifier;
import org.ripple.bouncycastle.asn1.x509.crlreason;
import org.ripple.bouncycastle.asn1.x509.x509certificatestructure;
import org.ripple.bouncycastle.asn1.x509.x509extensions;

/**
 * generator for basic ocsp response objects.
 *
 * @deprecated use classes in org.bouncycastle.cert.ocsp.
 */
public class basicocsprespgenerator
{
    private list            list = new arraylist();
    private x509extensions  responseextensions = null;
    private respid          responderid;

    private class responseobject
    {
        certificateid         certid;
        certstatus            certstatus;
        dergeneralizedtime    thisupdate;
        dergeneralizedtime    nextupdate;
        x509extensions        extensions;

        public responseobject(
            certificateid     certid,
            certificatestatus certstatus,
            date              thisupdate,
            date              nextupdate,
            x509extensions    extensions)
        {
            this.certid = certid;

            if (certstatus == null)
            {
                this.certstatus = new certstatus();
            }
            else if (certstatus instanceof unknownstatus)
            {
                this.certstatus = new certstatus(2, dernull.instance);
            }
            else 
            {
                revokedstatus rs = (revokedstatus)certstatus;
                
                if (rs.hasrevocationreason())
                {
                    this.certstatus = new certstatus(
                                            new revokedinfo(new asn1generalizedtime(rs.getrevocationtime()), crlreason.lookup(rs.getrevocationreason())));
                }
                else
                {
                    this.certstatus = new certstatus(
                                            new revokedinfo(new asn1generalizedtime(rs.getrevocationtime()), null));
                }
            }

            this.thisupdate = new dergeneralizedtime(thisupdate);
            
            if (nextupdate != null)
            {
                this.nextupdate = new dergeneralizedtime(nextupdate);
            }
            else
            {
                this.nextupdate = null;
            }

            this.extensions = extensions;
        }

        public singleresponse toresponse()
            throws exception
        {
            return new singleresponse(certid.toasn1object(), certstatus, thisupdate, nextupdate, extensions);
        }
    }

    /**
     * basic constructor
     */
    public basicocsprespgenerator(
        respid  responderid)
    {
        this.responderid = responderid;
    }

    /**
     * construct with the responderid to be the sha-1 keyhash of the passed in public key.
     */
    public basicocsprespgenerator(
        publickey       key)
        throws ocspexception
    {
        this.responderid = new respid(key);
    }

    /**
     * add a response for a particular certificate id.
     * 
     * @param certid certificate id details
     * @param certstatus status of the certificate - null if okay
     */
    public void addresponse(
        certificateid       certid,
        certificatestatus   certstatus)
    {
        list.add(new responseobject(certid, certstatus, new date(), null, null));
    }

    /**
     * add a response for a particular certificate id.
     * 
     * @param certid certificate id details
     * @param certstatus status of the certificate - null if okay
     * @param singleextensions optional extensions
     */
    public void addresponse(
        certificateid       certid,
        certificatestatus   certstatus,
        x509extensions      singleextensions)
    {
        list.add(new responseobject(certid, certstatus, new date(), null, singleextensions));
    }
    
    /**
     * add a response for a particular certificate id.
     * 
     * @param certid certificate id details
     * @param nextupdate date when next update should be requested
     * @param certstatus status of the certificate - null if okay
     * @param singleextensions optional extensions
     */
    public void addresponse(
        certificateid       certid,
        certificatestatus   certstatus,
        date                nextupdate,
        x509extensions      singleextensions)
    {
        list.add(new responseobject(certid, certstatus, new date(), nextupdate, singleextensions));
    }
    
    /**
     * add a response for a particular certificate id.
     * 
     * @param certid certificate id details
     * @param thisupdate date this response was valid on
     * @param nextupdate date when next update should be requested
     * @param certstatus status of the certificate - null if okay
     * @param singleextensions optional extensions
     */
    public void addresponse(
        certificateid       certid,
        certificatestatus   certstatus,
        date                thisupdate,
        date                nextupdate,
        x509extensions      singleextensions)
    {
        list.add(new responseobject(certid, certstatus, thisupdate, nextupdate, singleextensions));
    }
    
    /**
     * set the extensions for the response.
     * 
     * @param responseextensions the extension object to carry.
     */
    public void setresponseextensions(
        x509extensions  responseextensions)
    {
        this.responseextensions = responseextensions;
    }

    private basicocspresp generateresponse(
        string              signaturename,
        privatekey          key,
        x509certificate[]   chain,
        date                producedat,
        string              provider,
        securerandom        random)
        throws ocspexception, nosuchproviderexception
    {
        iterator    it = list.iterator();
        derobjectidentifier signingalgorithm;

        try
        {
            signingalgorithm = ocsputil.getalgorithmoid(signaturename);
        }
        catch (exception e)
        {
            throw new illegalargumentexception("unknown signing algorithm specified");
        }

        asn1encodablevector responses = new asn1encodablevector();

        while (it.hasnext())
        {
            try
            {
                responses.add(((responseobject)it.next()).toresponse());
            }
            catch (exception e)
            {
                throw new ocspexception("exception creating request", e);
            }
        }

        responsedata  tbsresp = new responsedata(responderid.toasn1object(), new dergeneralizedtime(producedat), new dersequence(responses), responseextensions);

        signature sig = null;

        try
        {
            sig = ocsputil.createsignatureinstance(signaturename, provider);
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
            sig.update(tbsresp.getencoded(asn1encoding.der));

            bitsig = new derbitstring(sig.sign());
        }
        catch (exception e)
        {
            throw new ocspexception("exception processing tbsrequest: " + e, e);
        }

        algorithmidentifier sigalgid = ocsputil.getsigalgid(signingalgorithm);

        dersequence chainseq = null;
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

            chainseq = new dersequence(v);
        }

        return new basicocspresp(new basicocspresponse(tbsresp, sigalgid, bitsig, chainseq));
    }
    
    public basicocspresp generate(
        string             signingalgorithm,
        privatekey         key,
        x509certificate[]  chain,
        date               thisupdate,
        string             provider)
        throws ocspexception, nosuchproviderexception, illegalargumentexception
    {
        return generate(signingalgorithm, key, chain, thisupdate, provider, null);
    }

    public basicocspresp generate(
        string             signingalgorithm,
        privatekey         key,
        x509certificate[]  chain,
        date               producedat,
        string             provider,
        securerandom       random)
        throws ocspexception, nosuchproviderexception, illegalargumentexception
    {
        if (signingalgorithm == null)
        {
            throw new illegalargumentexception("no signing algorithm specified");
        }

        return generateresponse(signingalgorithm, key, chain, producedat, provider, random);
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
