package org.ripple.bouncycastle.ocsp;

import java.io.bytearrayinputstream;
import java.io.bytearrayoutputstream;
import java.io.ioexception;
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
import java.text.parseexception;
import java.util.arraylist;
import java.util.date;
import java.util.enumeration;
import java.util.hashset;
import java.util.list;
import java.util.set;

import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1encoding;
import org.ripple.bouncycastle.asn1.asn1outputstream;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.derobjectidentifier;
import org.ripple.bouncycastle.asn1.ocsp.basicocspresponse;
import org.ripple.bouncycastle.asn1.ocsp.responsedata;
import org.ripple.bouncycastle.asn1.ocsp.singleresponse;
import org.ripple.bouncycastle.asn1.x509.x509extension;
import org.ripple.bouncycastle.asn1.x509.x509extensions;

/**
 * <pre>
 * basicocspresponse       ::= sequence {
 *    tbsresponsedata      responsedata,
 *    signaturealgorithm   algorithmidentifier,
 *    signature            bit string,
 *    certs                [0] explicit sequence of certificate optional }
 * </pre>
 *
 * @deprecated use classes in org.bouncycastle.cert.ocsp.
 */
public class basicocspresp
    implements java.security.cert.x509extension
{
    basicocspresponse   resp;
    responsedata        data;
    x509certificate[]   chain = null;

    public basicocspresp(
        basicocspresponse   resp)
    {
        this.resp = resp;
        this.data = resp.gettbsresponsedata();
    }

    /**
     * return the der encoding of the tbsresponsedata field.
     * @return der encoding of tbsresponsedata
     * @throws ocspexception in the event of an encoding error.
     */
    public byte[] gettbsresponsedata()
        throws ocspexception
    {
        try
        {
            return resp.gettbsresponsedata().getencoded();
        }
        catch (ioexception e)
        {
            throw new ocspexception("problem encoding tbsresponsedata", e);
        }
    }
    
    public int getversion()
    {
        return data.getversion().getvalue().intvalue() + 1;
    }

    public respid getresponderid()
    {
        return new respid(data.getresponderid());
    }

    public date getproducedat()
    {
        try
        {
            return data.getproducedat().getdate();
        }
        catch (parseexception e)
        {
            throw new illegalstateexception("parseexception:" + e.getmessage());
        }
    }

    public singleresp[] getresponses()
    {
        asn1sequence    s = data.getresponses();
        singleresp[]    rs = new singleresp[s.size()];

        for (int i = 0; i != rs.length; i++)
        {
            rs[i] = new singleresp(singleresponse.getinstance(s.getobjectat(i)));
        }

        return rs;
    }

    public x509extensions getresponseextensions()
    {
        return x509extensions.getinstance(data.getresponseextensions());
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
        x509extensions  extensions = this.getresponseextensions();
        
        if (extensions != null)
        {
            enumeration     e = extensions.oids();
    
            while (e.hasmoreelements())
            {
                derobjectidentifier oid = (derobjectidentifier)e.nextelement();
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
        x509extensions exts = this.getresponseextensions();

        if (exts != null)
        {
            x509extension   ext = exts.getextension(new derobjectidentifier(oid));

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

    public string getsignaturealgname()
    {
        return ocsputil.getalgorithmname(resp.getsignaturealgorithm().getobjectid());
    }

    public string getsignaturealgoid()
    {
        return resp.getsignaturealgorithm().getobjectid().getid();
    }

    /**
     * @deprecated respdata class is no longer required as all functionality is
     * available on this class.
     * @return the respdata object
     */
    public respdata getresponsedata()
    {
        return new respdata(resp.gettbsresponsedata());
    }

    public byte[] getsignature()
    {
        return resp.getsignature().getbytes();
    }

    private list getcertlist(
        string provider) 
        throws ocspexception, nosuchproviderexception
    {
        list                    certs = new arraylist();
        bytearrayoutputstream   bout = new bytearrayoutputstream();
        asn1outputstream        aout = new asn1outputstream(bout);
        certificatefactory      cf;

        try
        {
            cf = ocsputil.createx509certificatefactory(provider);
        }
        catch (certificateexception ex)
        {
            throw new ocspexception("can't get certificate factory.", ex);
        }

        //
        // load the certificates and revocation lists if we have any
        //
        asn1sequence s = resp.getcerts();

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
        list                    certs = getcertlist(provider);
            
        return (x509certificate[])certs.toarray(new x509certificate[certs.size()]);
    }

    /**
     * return the certificates, if any associated with the response.
     * @param type type of certstore to create
     * @param provider provider to use
     * @return a certstore, possibly empty
     * @throws nosuchalgorithmexception
     * @throws nosuchproviderexception
     * @throws ocspexception
     */
    public certstore getcertificates(
        string type,
        string provider) 
        throws nosuchalgorithmexception, nosuchproviderexception, ocspexception
    {
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
     * verify the signature against the tbsresponsedata object we contain.
     */
    public boolean verify(
        publickey   key,
        string      sigprovider)
        throws ocspexception, nosuchproviderexception
    {
        try
        {
            signature signature = ocsputil.createsignatureinstance(this.getsignaturealgname(), sigprovider);

            signature.initverify(key);

            signature.update(resp.gettbsresponsedata().getencoded(asn1encoding.der));

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
        return resp.getencoded();
    }
    
    public boolean equals(object o)
    {
        if (o == this)
        {
            return true;
        }
        
        if (!(o instanceof basicocspresp))
        {
            return false;
        }
        
        basicocspresp r = (basicocspresp)o;
        
        return resp.equals(r.resp);
    }
    
    public int hashcode()
    {
        return resp.hashcode();
    }
}
