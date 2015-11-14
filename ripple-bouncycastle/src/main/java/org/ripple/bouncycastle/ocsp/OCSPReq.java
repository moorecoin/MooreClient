package org.ripple.bouncycastle.ocsp;

import java.io.bytearrayinputstream;
import java.io.bytearrayoutputstream;
import java.io.ioexception;
import java.io.inputstream;
import java.security.invalidalgorithmparameterexception;
import java.security.nosuchalgorithmexception;
import java.security.nosuchproviderexception;
import java.security.publickey;
import java.security.signature;
import java.security.cert.certstore;
import java.security.cert.certstoreparameters;
import java.security.cert.certificateexception;
import java.security.cert.certificatefactory;
import java.security.cert.collectioncertstoreparameters;
import java.security.cert.x509certificate;
import java.util.arraylist;
import java.util.enumeration;
import java.util.hashset;
import java.util.list;
import java.util.set;

import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1encoding;
import org.ripple.bouncycastle.asn1.asn1inputstream;
import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.asn1outputstream;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.ocsp.ocsprequest;
import org.ripple.bouncycastle.asn1.ocsp.request;
import org.ripple.bouncycastle.asn1.x509.generalname;
import org.ripple.bouncycastle.asn1.x509.x509extension;
import org.ripple.bouncycastle.asn1.x509.x509extensions;

/**
 * <pre>
 * ocsprequest     ::=     sequence {
 *       tbsrequest                  tbsrequest,
 *       optionalsignature   [0]     explicit signature optional }
 *
 *   tbsrequest      ::=     sequence {
 *       version             [0]     explicit version default v1,
 *       requestorname       [1]     explicit generalname optional,
 *       requestlist                 sequence of request,
 *       requestextensions   [2]     explicit extensions optional }
 *
 *   signature       ::=     sequence {
 *       signaturealgorithm      algorithmidentifier,
 *       signature               bit string,
 *       certs               [0] explicit sequence of certificate optional}
 *
 *   version         ::=             integer  {  v1(0) }
 *
 *   request         ::=     sequence {
 *       reqcert                     certid,
 *       singlerequestextensions     [0] explicit extensions optional }
 *
 *   certid          ::=     sequence {
 *       hashalgorithm       algorithmidentifier,
 *       issuernamehash      octet string, -- hash of issuer's dn
 *       issuerkeyhash       octet string, -- hash of issuers public key
 *       serialnumber        certificateserialnumber }
 * </pre>
 *
 * @deprecated use classes in org.bouncycastle.cert.ocsp.
 */
public class ocspreq
    implements java.security.cert.x509extension
{
    private ocsprequest       req;

    public ocspreq(
        ocsprequest req)
    {
        this.req = req;
    }
    
    public ocspreq(
        byte[]          req)
        throws ioexception
    {
        this(new asn1inputstream(req));
    }

    public ocspreq(
        inputstream     in)
        throws ioexception
    {
        this(new asn1inputstream(in));
    }

    private ocspreq(
        asn1inputstream ain) 
        throws ioexception
    {
        try
        {
            this.req = ocsprequest.getinstance(ain.readobject());
        }
        catch (illegalargumentexception e)
        {
            throw new ioexception("malformed request: " + e.getmessage());
        }
        catch (classcastexception e)
        {
            throw new ioexception("malformed request: " + e.getmessage());
        }
    }

    /**
     * return the der encoding of the tbsrequest field.
     * @return der encoding of tbsrequest
     * @throws ocspexception in the event of an encoding error.
     */
    public byte[] gettbsrequest()
        throws ocspexception
    {
        try
        {
            return req.gettbsrequest().getencoded();
        }
        catch (ioexception e)
        {
            throw new ocspexception("problem encoding tbsrequest", e);
        }
    }
    
    public int getversion()
    {
        return req.gettbsrequest().getversion().getvalue().intvalue() + 1;
    }
    
    public generalname getrequestorname()
    {
        return generalname.getinstance(req.gettbsrequest().getrequestorname());
    }

    public req[] getrequestlist()
    {
        asn1sequence    seq = req.gettbsrequest().getrequestlist();
        req[]           requests = new req[seq.size()];

        for (int i = 0; i != requests.length; i++)
        {
            requests[i] = new req(request.getinstance(seq.getobjectat(i)));
        }

        return requests;
    }

    public x509extensions getrequestextensions()
    {
        return x509extensions.getinstance(req.gettbsrequest().getrequestextensions());
    }

    /**
     * return the object identifier representing the signature algorithm
     */
    public string getsignaturealgoid()
    {
        if (!this.issigned())
        {
            return null;
        }

        return req.getoptionalsignature().getsignaturealgorithm().getobjectid().getid();
    }

    public byte[] getsignature()
    {
        if (!this.issigned())
        {
            return null;
        }

        return req.getoptionalsignature().getsignature().getbytes();
    }
    
    private list getcertlist(
        string provider) 
        throws ocspexception, nosuchproviderexception
    {
        list                  certs = new arraylist();
        bytearrayoutputstream bout = new bytearrayoutputstream();
        asn1outputstream      aout = new asn1outputstream(bout);
        certificatefactory    cf;

        try
        {
            cf = ocsputil.createx509certificatefactory(provider);
        }
        catch (certificateexception ex)
        {
            throw new ocspexception("can't get certificate factory.", ex);
        }

        //
        // load the certificates if we have any
        //
        asn1sequence s = req.getoptionalsignature().getcerts();

        if (s != null)
        {
            enumeration e = s.getobjects();

            while (e.hasmoreelements())
            {
                try
                {
                    aout.writeobject((asn1encodable)e.nextelement());

                    certs.add(cf.generatecertificate(
                        new bytearrayinputstream(bout.tobytearray())));
                }
                catch (ioexception ex)
                {
                    throw new ocspexception(
                            "can't re-encode certificate!", ex);
                }
                catch (certificateexception ex)
                {
                    throw new ocspexception(
                            "can't re-encode certificate!", ex);
                }

                bout.reset();
            }
        }
        
        return certs;
    }
    
    public x509certificate[] getcerts(
        string  provider)
        throws ocspexception, nosuchproviderexception
    {
        if (!this.issigned())
        {
            return null;
        }
    
        list         certs = this.getcertlist(provider);
        
        return (x509certificate[])certs.toarray(new x509certificate[certs.size()]);
    }
    
    /**
     * if the request is signed return a possibly empty certstore containing the certificates in the
     * request. if the request is not signed the method returns null.
     * 
     * @param type type of certstore to return
     * @param provider provider to use
     * @return null if not signed, a certstore otherwise
     * @throws nosuchalgorithmexception
     * @throws nosuchproviderexception
     * @throws ocspexception
     */
    public certstore getcertificates(
        string type,
        string provider) 
        throws nosuchalgorithmexception, nosuchproviderexception, ocspexception
    {
        if (!this.issigned())
        {
            return null;
        }
        
        try
        {
            certstoreparameters params = new collectioncertstoreparameters(this.getcertlist(provider));
            return ocsputil.createcertstoreinstance(type, params, provider);
        }
        catch (invalidalgorithmparameterexception e)
        {
            throw new ocspexception("can't setup the certstore", e);
        }
    }
    
    /**
     * return whether or not this request is signed.
     * 
     * @return true if signed false otherwise.
     */
    public boolean issigned()
    {
        return req.getoptionalsignature() != null;
    }

    /**
     * verify the signature against the tbsrequest object we contain.
     */
    public boolean verify(
        publickey   key,
        string      sigprovider)
        throws ocspexception, nosuchproviderexception
    {
        if (!this.issigned())
        {
            throw new ocspexception("attempt to verify signature on unsigned object");
        }

        try
        {
            signature signature = ocsputil.createsignatureinstance(this.getsignaturealgoid(), sigprovider);

            signature.initverify(key);

            bytearrayoutputstream   bout = new bytearrayoutputstream();
            asn1outputstream        aout = new asn1outputstream(bout);

            aout.writeobject(req.gettbsrequest());

            signature.update(bout.tobytearray());

            return signature.verify(this.getsignature());
        }
        catch (nosuchproviderexception e)
        {
            // todo why this special case?
            throw e;
        }
        catch (exception e)
        {
            throw new ocspexception("exception processing sig: " + e, e);
        }
    }

    /**
     * return the asn.1 encoded representation of this object.
     */
    public byte[] getencoded()
        throws ioexception
    {
        bytearrayoutputstream   bout = new bytearrayoutputstream();
        asn1outputstream        aout = new asn1outputstream(bout);

        aout.writeobject(req);

        return bout.tobytearray();
    }

    /**
     * rfc 2650 doesn't specify any critical extensions so we return true
     * if any are encountered.
     * 
     * @return true if any critical extensions are present.
     */
    public boolean hasunsupportedcriticalextension()
    {
        set extns = getcriticalextensionoids();
        if (extns != null && !extns.isempty())
        {
            return true;
        }

        return false;
    }

    private set getextensionoids(boolean critical)
    {
        set             set = new hashset();
        x509extensions  extensions = this.getrequestextensions();
        
        if (extensions != null)
        {
            enumeration     e = extensions.oids();
    
            while (e.hasmoreelements())
            {
                asn1objectidentifier oid = (asn1objectidentifier)e.nextelement();
                x509extension       ext = extensions.getextension(oid);
    
                if (critical == ext.iscritical())
                {
                    set.add(oid.getid());
                }
            }
        }

        return set;
    }

    public set getcriticalextensionoids()
    {
        return getextensionoids(true);
    }

    public set getnoncriticalextensionoids()
    {
        return getextensionoids(false);
    }

    public byte[] getextensionvalue(string oid)
    {
        x509extensions exts = this.getrequestextensions();

        if (exts != null)
        {
            x509extension   ext = exts.getextension(new asn1objectidentifier(oid));

            if (ext != null)
            {
                try
                {
                    return ext.getvalue().getencoded(asn1encoding.der);
                }
                catch (exception e)
                {
                    throw new runtimeexception("error encoding " + e.tostring());
                }
            }
        }

        return null;
    }
}
