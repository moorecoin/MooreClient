package org.ripple.bouncycastle.jcajce.provider.asymmetric.x509;

import java.io.bufferedinputstream;
import java.io.bytearrayinputstream;
import java.io.bytearrayoutputstream;
import java.io.ioexception;
import java.io.inputstream;
import java.io.outputstreamwriter;
import java.security.nosuchproviderexception;
import java.security.cert.certpath;
import java.security.cert.certificate;
import java.security.cert.certificateencodingexception;
import java.security.cert.certificateexception;
import java.security.cert.certificatefactory;
import java.security.cert.x509certificate;
import java.util.arraylist;
import java.util.collections;
import java.util.enumeration;
import java.util.iterator;
import java.util.list;
import java.util.listiterator;

import javax.security.auth.x500.x500principal;

import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1encoding;
import org.ripple.bouncycastle.asn1.asn1inputstream;
import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.derset;
import org.ripple.bouncycastle.asn1.pkcs.contentinfo;
import org.ripple.bouncycastle.asn1.pkcs.pkcsobjectidentifiers;
import org.ripple.bouncycastle.asn1.pkcs.signeddata;
import org.ripple.bouncycastle.jce.provider.bouncycastleprovider;
import org.ripple.bouncycastle.util.io.pem.pemobject;
import org.ripple.bouncycastle.util.io.pem.pemwriter;

/**
 * certpath implementation for x.509 certificates.
 * <br />
 **/
public  class pkixcertpath
    extends certpath
{
    static final list certpathencodings;

    static
    {
        list encodings = new arraylist();
        encodings.add("pkipath");
        encodings.add("pem");
        encodings.add("pkcs7");
        certpathencodings = collections.unmodifiablelist(encodings);
    }

    private list certificates;

    /**
     * @param certs
     */
    private list sortcerts(
        list certs)
    {
        if (certs.size() < 2)
        {
            return certs;
        }
        
        x500principal issuer = ((x509certificate)certs.get(0)).getissuerx500principal();
        boolean         okay = true;
        
        for (int i = 1; i != certs.size(); i++) 
        {
            x509certificate cert = (x509certificate)certs.get(i);
            
            if (issuer.equals(cert.getsubjectx500principal()))
            {
                issuer = ((x509certificate)certs.get(i)).getissuerx500principal();
            }
            else
            {
                okay = false;
                break;
            }
        }
        
        if (okay)
        {
            return certs;
        }
        
        // find end-entity cert
        list retlist = new arraylist(certs.size());
        list orig = new arraylist(certs);

        for (int i = 0; i < certs.size(); i++)
        {
            x509certificate cert = (x509certificate)certs.get(i);
            boolean         found = false;
            
            x500principal subject = cert.getsubjectx500principal();
            
            for (int j = 0; j != certs.size(); j++)
            {
                x509certificate c = (x509certificate)certs.get(j);
                if (c.getissuerx500principal().equals(subject))
                {
                    found = true;
                    break;
                }
            }
            
            if (!found)
            {
                retlist.add(cert);
                certs.remove(i);
            }
        }
        
        // can only have one end entity cert - something's wrong, give up.
        if (retlist.size() > 1)
        {
            return orig;
        }

        for (int i = 0; i != retlist.size(); i++)
        {
            issuer = ((x509certificate)retlist.get(i)).getissuerx500principal();
            
            for (int j = 0; j < certs.size(); j++)
            {
                x509certificate c = (x509certificate)certs.get(j);
                if (issuer.equals(c.getsubjectx500principal()))
                {
                    retlist.add(c);
                    certs.remove(j);
                    break;
                }
            }
        }
        
        // make sure all certificates are accounted for.
        if (certs.size() > 0)
        {
            return orig;
        }
        
        return retlist;
    }

    pkixcertpath(list certificates)
    {
        super("x.509");
        this.certificates = sortcerts(new arraylist(certificates));
    }

    /**
     * creates a certpath of the specified type.
     * this constructor is protected because most users should use
     * a certificatefactory to create certpaths.
     **/
    pkixcertpath(
        inputstream instream,
        string encoding)
        throws certificateexception
    {
        super("x.509");
        try
        {
            if (encoding.equalsignorecase("pkipath"))
            {
                asn1inputstream derinstream = new asn1inputstream(instream);
                asn1primitive derobject = derinstream.readobject();
                if (!(derobject instanceof asn1sequence))
                {
                    throw new certificateexception("input stream does not contain a asn1 sequence while reading pkipath encoded data to load certpath");
                }
                enumeration e = ((asn1sequence)derobject).getobjects();
                certificates = new arraylist();
                certificatefactory certfactory = certificatefactory.getinstance("x.509", bouncycastleprovider.provider_name);
                while (e.hasmoreelements())
                {
                    asn1encodable element = (asn1encodable)e.nextelement();
                    byte[] encoded = element.toasn1primitive().getencoded(asn1encoding.der);
                    certificates.add(0, certfactory.generatecertificate(
                        new bytearrayinputstream(encoded)));
                }
            }
            else if (encoding.equalsignorecase("pkcs7") || encoding.equalsignorecase("pem"))
            {
                instream = new bufferedinputstream(instream);
                certificates = new arraylist();
                certificatefactory certfactory= certificatefactory.getinstance("x.509", bouncycastleprovider.provider_name);
                certificate cert;
                while ((cert = certfactory.generatecertificate(instream)) != null)
                {
                    certificates.add(cert);
                }
            }
            else
            {
                throw new certificateexception("unsupported encoding: " + encoding);
            }
        }
        catch (ioexception ex)
        {
            throw new certificateexception("ioexception throw while decoding certpath:\n" + ex.tostring());
        }
        catch (nosuchproviderexception ex)
        {
            throw new certificateexception("bouncycastle provider not found while trying to get a certificatefactory:\n" + ex.tostring());
        }
        
        this.certificates = sortcerts(certificates);
    }
    
    /**
     * returns an iteration of the encodings supported by this
     * certification path, with the default encoding
     * first. attempts to modify the returned iterator via its
     * remove method result in an unsupportedoperationexception.
     *
     * @return an iterator over the names of the supported encodings (as strings)
     **/
    public iterator getencodings()
    {
        return certpathencodings.iterator();
    }

    /**
     * returns the encoded form of this certification path, using
     * the default encoding.
     *
     * @return the encoded bytes
     * @exception java.security.cert.certificateencodingexception if an encoding error occurs
     **/
    public byte[] getencoded()
        throws certificateencodingexception
    {
        iterator iter = getencodings();
        if (iter.hasnext())
        {
            object enc = iter.next();
            if (enc instanceof string)
            {
            return getencoded((string)enc);
            }
        }
        return null;
    }

    /**
     * returns the encoded form of this certification path, using
     * the specified encoding.
     *
     * @param encoding the name of the encoding to use
     * @return the encoded bytes
     * @exception java.security.cert.certificateencodingexception if an encoding error
     * occurs or the encoding requested is not supported
     *
     **/
    public byte[] getencoded(string encoding)
        throws certificateencodingexception
    {
        if (encoding.equalsignorecase("pkipath"))
        {
            asn1encodablevector v = new asn1encodablevector();

            listiterator iter = certificates.listiterator(certificates.size());
            while (iter.hasprevious())
            {
                v.add(toasn1object((x509certificate)iter.previous()));
            }

            return toderencoded(new dersequence(v));
        }
        else if (encoding.equalsignorecase("pkcs7"))
        {
            contentinfo encinfo = new contentinfo(pkcsobjectidentifiers.data, null);

            asn1encodablevector v = new asn1encodablevector();
            for (int i = 0; i != certificates.size(); i++)
            {
                v.add(toasn1object((x509certificate)certificates.get(i)));
            }
            
            signeddata sd = new signeddata(
                                     new asn1integer(1),
                                     new derset(),
                                     encinfo, 
                                     new derset(v),
                                     null, 
                                     new derset());

            return toderencoded(new contentinfo(
                    pkcsobjectidentifiers.signeddata, sd));
        }
        else if (encoding.equalsignorecase("pem"))
        {
            bytearrayoutputstream bout = new bytearrayoutputstream();
            pemwriter pwrt = new pemwriter(new outputstreamwriter(bout));

            try
            {
                for (int i = 0; i != certificates.size(); i++)
                {
                    pwrt.writeobject(new pemobject("certificate", ((x509certificate)certificates.get(i)).getencoded()));
                }
            
                pwrt.close();
            }
            catch (exception e)
            {
                throw new certificateencodingexception("can't encode certificate for pem encoded path");
            }

            return bout.tobytearray();
        }
        else
        {
            throw new certificateencodingexception("unsupported encoding: " + encoding);
        }
    }

    /**
     * returns the list of certificates in this certification
     * path. the list returned must be immutable and thread-safe. 
     *
     * @return an immutable list of certificates (may be empty, but not null)
     **/
    public list getcertificates()
    {
        return collections.unmodifiablelist(new arraylist(certificates));
    }

    /**
     * return a derobject containing the encoded certificate.
     *
     * @param cert the x509certificate object to be encoded
     *
     * @return the derobject
     **/
    private asn1primitive toasn1object(
        x509certificate cert)
        throws certificateencodingexception
    {
        try
        {
            return new asn1inputstream(cert.getencoded()).readobject();
        }
        catch (exception e)
        {
            throw new certificateencodingexception("exception while encoding certificate: " + e.tostring());
        }
    }
    
    private byte[] toderencoded(asn1encodable obj)
        throws certificateencodingexception
    {
        try
        {
            return obj.toasn1primitive().getencoded(asn1encoding.der);
        }
        catch (ioexception e)
        {
            throw new certificateencodingexception("exception thrown: " + e);
        }
    }
}
