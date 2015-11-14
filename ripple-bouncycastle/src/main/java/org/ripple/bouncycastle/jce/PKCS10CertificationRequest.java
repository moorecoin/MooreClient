package org.ripple.bouncycastle.jce;

import java.io.ioexception;
import java.security.algorithmparameters;
import java.security.generalsecurityexception;
import java.security.invalidkeyexception;
import java.security.keyfactory;
import java.security.nosuchalgorithmexception;
import java.security.nosuchproviderexception;
import java.security.privatekey;
import java.security.publickey;
import java.security.signature;
import java.security.signatureexception;
import java.security.spec.invalidkeyspecexception;
import java.security.spec.pssparameterspec;
import java.security.spec.x509encodedkeyspec;
import java.util.hashset;
import java.util.hashtable;
import java.util.set;

import javax.security.auth.x500.x500principal;

import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1encoding;
import org.ripple.bouncycastle.asn1.asn1inputstream;
import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1set;
import org.ripple.bouncycastle.asn1.derbitstring;
import org.ripple.bouncycastle.asn1.dernull;
import org.ripple.bouncycastle.asn1.derobjectidentifier;
import org.ripple.bouncycastle.asn1.cryptopro.cryptoproobjectidentifiers;
import org.ripple.bouncycastle.asn1.nist.nistobjectidentifiers;
import org.ripple.bouncycastle.asn1.oiw.oiwobjectidentifiers;
import org.ripple.bouncycastle.asn1.pkcs.certificationrequest;
import org.ripple.bouncycastle.asn1.pkcs.certificationrequestinfo;
import org.ripple.bouncycastle.asn1.pkcs.pkcsobjectidentifiers;
import org.ripple.bouncycastle.asn1.pkcs.rsassapssparams;
import org.ripple.bouncycastle.asn1.teletrust.teletrustobjectidentifiers;
import org.ripple.bouncycastle.asn1.x509.algorithmidentifier;
import org.ripple.bouncycastle.asn1.x509.subjectpublickeyinfo;
import org.ripple.bouncycastle.asn1.x509.x509name;
import org.ripple.bouncycastle.asn1.x9.x9objectidentifiers;
import org.ripple.bouncycastle.jce.provider.bouncycastleprovider;
import org.ripple.bouncycastle.util.strings;

/**
 * a class for verifying and creating pkcs10 certification requests. 
 * <pre>
 * certificationrequest ::= sequence {
 *   certificationrequestinfo  certificationrequestinfo,
 *   signaturealgorithm        algorithmidentifier{{ signaturealgorithms }},
 *   signature                 bit string
 * }
 *
 * certificationrequestinfo ::= sequence {
 *   version             integer { v1(0) } (v1,...),
 *   subject             name,
 *   subjectpkinfo   subjectpublickeyinfo{{ pkinfoalgorithms }},
 *   attributes          [0] attributes{{ criattributes }}
 *  }
 *
 *  attributes { attribute:ioset } ::= set of attribute{{ ioset }}
 *
 *  attribute { attribute:ioset } ::= sequence {
 *    type    attribute.&id({ioset}),
 *    values  set size(1..max) of attribute.&type({ioset}{\@type})
 *  }
 * </pre>
 * @deprecated use classes in org.bouncycastle.pkcs.
 */
public class pkcs10certificationrequest
    extends certificationrequest
{
    private static hashtable            algorithms = new hashtable();
    private static hashtable            params = new hashtable();
    private static hashtable            keyalgorithms = new hashtable();
    private static hashtable            oids = new hashtable();
    private static set                  noparams = new hashset();

    static
    {
        algorithms.put("md2withrsaencryption", new derobjectidentifier("1.2.840.113549.1.1.2"));
        algorithms.put("md2withrsa", new derobjectidentifier("1.2.840.113549.1.1.2"));
        algorithms.put("md5withrsaencryption", new derobjectidentifier("1.2.840.113549.1.1.4"));
        algorithms.put("md5withrsa", new derobjectidentifier("1.2.840.113549.1.1.4"));
        algorithms.put("rsawithmd5", new derobjectidentifier("1.2.840.113549.1.1.4"));
        algorithms.put("sha1withrsaencryption", new derobjectidentifier("1.2.840.113549.1.1.5"));
        algorithms.put("sha1withrsa", new derobjectidentifier("1.2.840.113549.1.1.5"));
        algorithms.put("sha224withrsaencryption", pkcsobjectidentifiers.sha224withrsaencryption);
        algorithms.put("sha224withrsa", pkcsobjectidentifiers.sha224withrsaencryption);
        algorithms.put("sha256withrsaencryption", pkcsobjectidentifiers.sha256withrsaencryption);
        algorithms.put("sha256withrsa", pkcsobjectidentifiers.sha256withrsaencryption);
        algorithms.put("sha384withrsaencryption", pkcsobjectidentifiers.sha384withrsaencryption);
        algorithms.put("sha384withrsa", pkcsobjectidentifiers.sha384withrsaencryption);
        algorithms.put("sha512withrsaencryption", pkcsobjectidentifiers.sha512withrsaencryption);
        algorithms.put("sha512withrsa", pkcsobjectidentifiers.sha512withrsaencryption);
        algorithms.put("sha1withrsaandmgf1", pkcsobjectidentifiers.id_rsassa_pss);
        algorithms.put("sha224withrsaandmgf1", pkcsobjectidentifiers.id_rsassa_pss);
        algorithms.put("sha256withrsaandmgf1", pkcsobjectidentifiers.id_rsassa_pss);
        algorithms.put("sha384withrsaandmgf1", pkcsobjectidentifiers.id_rsassa_pss);
        algorithms.put("sha512withrsaandmgf1", pkcsobjectidentifiers.id_rsassa_pss);
        algorithms.put("rsawithsha1", new derobjectidentifier("1.2.840.113549.1.1.5"));
        algorithms.put("ripemd128withrsaencryption", teletrustobjectidentifiers.rsasignaturewithripemd128);
        algorithms.put("ripemd128withrsa", teletrustobjectidentifiers.rsasignaturewithripemd128);
        algorithms.put("ripemd160withrsaencryption", teletrustobjectidentifiers.rsasignaturewithripemd160);
        algorithms.put("ripemd160withrsa", teletrustobjectidentifiers.rsasignaturewithripemd160);
        algorithms.put("ripemd256withrsaencryption", teletrustobjectidentifiers.rsasignaturewithripemd256);
        algorithms.put("ripemd256withrsa", teletrustobjectidentifiers.rsasignaturewithripemd256);
        algorithms.put("sha1withdsa", new derobjectidentifier("1.2.840.10040.4.3"));
        algorithms.put("dsawithsha1", new derobjectidentifier("1.2.840.10040.4.3"));
        algorithms.put("sha224withdsa", nistobjectidentifiers.dsa_with_sha224);
        algorithms.put("sha256withdsa", nistobjectidentifiers.dsa_with_sha256);
        algorithms.put("sha384withdsa", nistobjectidentifiers.dsa_with_sha384);
        algorithms.put("sha512withdsa", nistobjectidentifiers.dsa_with_sha512);
        algorithms.put("sha1withecdsa", x9objectidentifiers.ecdsa_with_sha1);
        algorithms.put("sha224withecdsa", x9objectidentifiers.ecdsa_with_sha224);
        algorithms.put("sha256withecdsa", x9objectidentifiers.ecdsa_with_sha256);
        algorithms.put("sha384withecdsa", x9objectidentifiers.ecdsa_with_sha384);
        algorithms.put("sha512withecdsa", x9objectidentifiers.ecdsa_with_sha512);
        algorithms.put("ecdsawithsha1", x9objectidentifiers.ecdsa_with_sha1);
        algorithms.put("gost3411withgost3410", cryptoproobjectidentifiers.gostr3411_94_with_gostr3410_94);
        algorithms.put("gost3410withgost3411", cryptoproobjectidentifiers.gostr3411_94_with_gostr3410_94);
        algorithms.put("gost3411withecgost3410", cryptoproobjectidentifiers.gostr3411_94_with_gostr3410_2001);
        algorithms.put("gost3411withecgost3410-2001", cryptoproobjectidentifiers.gostr3411_94_with_gostr3410_2001);
        algorithms.put("gost3411withgost3410-2001", cryptoproobjectidentifiers.gostr3411_94_with_gostr3410_2001);

        //
        // reverse mappings
        //
        oids.put(new derobjectidentifier("1.2.840.113549.1.1.5"), "sha1withrsa");
        oids.put(pkcsobjectidentifiers.sha224withrsaencryption, "sha224withrsa");
        oids.put(pkcsobjectidentifiers.sha256withrsaencryption, "sha256withrsa");
        oids.put(pkcsobjectidentifiers.sha384withrsaencryption, "sha384withrsa");
        oids.put(pkcsobjectidentifiers.sha512withrsaencryption, "sha512withrsa");
        oids.put(cryptoproobjectidentifiers.gostr3411_94_with_gostr3410_94, "gost3411withgost3410");
        oids.put(cryptoproobjectidentifiers.gostr3411_94_with_gostr3410_2001, "gost3411withecgost3410");
        
        oids.put(new derobjectidentifier("1.2.840.113549.1.1.4"), "md5withrsa");
        oids.put(new derobjectidentifier("1.2.840.113549.1.1.2"), "md2withrsa");
        oids.put(new derobjectidentifier("1.2.840.10040.4.3"), "sha1withdsa");
        oids.put(x9objectidentifiers.ecdsa_with_sha1, "sha1withecdsa");
        oids.put(x9objectidentifiers.ecdsa_with_sha224, "sha224withecdsa");
        oids.put(x9objectidentifiers.ecdsa_with_sha256, "sha256withecdsa");
        oids.put(x9objectidentifiers.ecdsa_with_sha384, "sha384withecdsa");
        oids.put(x9objectidentifiers.ecdsa_with_sha512, "sha512withecdsa");
        oids.put(oiwobjectidentifiers.sha1withrsa, "sha1withrsa");
        oids.put(oiwobjectidentifiers.dsawithsha1, "sha1withdsa");
        oids.put(nistobjectidentifiers.dsa_with_sha224, "sha224withdsa");
        oids.put(nistobjectidentifiers.dsa_with_sha256, "sha256withdsa");
        
        //
        // key types
        //
        keyalgorithms.put(pkcsobjectidentifiers.rsaencryption, "rsa");
        keyalgorithms.put(x9objectidentifiers.id_dsa, "dsa");
        
        //
        // according to rfc 3279, the asn.1 encoding shall (id-dsa-with-sha1) or must (ecdsa-with-sha*) omit the parameters field. 
        // the parameters field shall be null for rsa based signature algorithms.
        //
        noparams.add(x9objectidentifiers.ecdsa_with_sha1);
        noparams.add(x9objectidentifiers.ecdsa_with_sha224);
        noparams.add(x9objectidentifiers.ecdsa_with_sha256);
        noparams.add(x9objectidentifiers.ecdsa_with_sha384);
        noparams.add(x9objectidentifiers.ecdsa_with_sha512);
        noparams.add(x9objectidentifiers.id_dsa_with_sha1);
        noparams.add(nistobjectidentifiers.dsa_with_sha224);
        noparams.add(nistobjectidentifiers.dsa_with_sha256);

        //
        // rfc 4491
        //
        noparams.add(cryptoproobjectidentifiers.gostr3411_94_with_gostr3410_94);
        noparams.add(cryptoproobjectidentifiers.gostr3411_94_with_gostr3410_2001);
        //
        // explicit params
        //
        algorithmidentifier sha1algid = new algorithmidentifier(oiwobjectidentifiers.idsha1, dernull.instance);
        params.put("sha1withrsaandmgf1", creatpssparams(sha1algid, 20));

        algorithmidentifier sha224algid = new algorithmidentifier(nistobjectidentifiers.id_sha224, dernull.instance);
        params.put("sha224withrsaandmgf1", creatpssparams(sha224algid, 28));

        algorithmidentifier sha256algid = new algorithmidentifier(nistobjectidentifiers.id_sha256, dernull.instance);
        params.put("sha256withrsaandmgf1", creatpssparams(sha256algid, 32));

        algorithmidentifier sha384algid = new algorithmidentifier(nistobjectidentifiers.id_sha384, dernull.instance);
        params.put("sha384withrsaandmgf1", creatpssparams(sha384algid, 48));

        algorithmidentifier sha512algid = new algorithmidentifier(nistobjectidentifiers.id_sha512, dernull.instance);
        params.put("sha512withrsaandmgf1", creatpssparams(sha512algid, 64));
    }

    private static rsassapssparams creatpssparams(algorithmidentifier hashalgid, int saltsize)
    {
        return new rsassapssparams(
            hashalgid,
            new algorithmidentifier(pkcsobjectidentifiers.id_mgf1, hashalgid),
            new asn1integer(saltsize),
            new asn1integer(1));
    }

    private static asn1sequence todersequence(
        byte[]  bytes)
    {
        try
        {
            asn1inputstream         din = new asn1inputstream(bytes);

            return (asn1sequence)din.readobject();
        }
        catch (exception e)
        {
            throw new illegalargumentexception("badly encoded request");
        }
    }

    /**
     * construct a pkcs10 certification request from a der encoded
     * byte stream.
     */
    public pkcs10certificationrequest(
        byte[]  bytes)
    {
        super(todersequence(bytes));
    }

    public pkcs10certificationrequest(
        asn1sequence  sequence)
    {
        super(sequence);
    }

    /**
     * create a pkcs10 certfication request using the bc provider.
     */
    public pkcs10certificationrequest(
        string              signaturealgorithm,
        x509name            subject,
        publickey           key,
        asn1set             attributes,
        privatekey          signingkey)
        throws nosuchalgorithmexception, nosuchproviderexception,
                invalidkeyexception, signatureexception
    {
        this(signaturealgorithm, subject, key, attributes, signingkey, bouncycastleprovider.provider_name);
    }

    private static x509name convertname(
        x500principal    name)
    {
        try
        {
            return new x509principal(name.getencoded());
        }
        catch (ioexception e)
        {
            throw new illegalargumentexception("can't convert name");
        }
    }
    
    /**
     * create a pkcs10 certfication request using the bc provider.
     */
    public pkcs10certificationrequest(
        string              signaturealgorithm,
        x500principal       subject,
        publickey           key,
        asn1set             attributes,
        privatekey          signingkey)
        throws nosuchalgorithmexception, nosuchproviderexception,
                invalidkeyexception, signatureexception
    {
        this(signaturealgorithm, convertname(subject), key, attributes, signingkey, bouncycastleprovider.provider_name);
    }
    
    /**
     * create a pkcs10 certfication request using the named provider.
     */
    public pkcs10certificationrequest(
        string              signaturealgorithm,
        x500principal       subject,
        publickey           key,
        asn1set             attributes,
        privatekey          signingkey,
        string              provider)
        throws nosuchalgorithmexception, nosuchproviderexception,
                invalidkeyexception, signatureexception
    {
        this(signaturealgorithm, convertname(subject), key, attributes, signingkey, provider);
    }
    
    /**
     * create a pkcs10 certfication request using the named provider.
     */
    public pkcs10certificationrequest(
        string              signaturealgorithm,
        x509name            subject,
        publickey           key,
        asn1set             attributes,
        privatekey          signingkey,
        string              provider)
        throws nosuchalgorithmexception, nosuchproviderexception,
                invalidkeyexception, signatureexception
    {
        string algorithmname = strings.touppercase(signaturealgorithm);
        derobjectidentifier sigoid = (derobjectidentifier)algorithms.get(algorithmname);

        if (sigoid == null)
        {
            try
            {
                sigoid = new derobjectidentifier(algorithmname);
            }
            catch (exception e)
            {
                throw new illegalargumentexception("unknown signature type requested");
            }
        }

        if (subject == null)
        {
            throw new illegalargumentexception("subject must not be null");
        }

        if (key == null)
        {
            throw new illegalargumentexception("public key must not be null");
        }

        if (noparams.contains(sigoid))
        {
            this.sigalgid = new algorithmidentifier(sigoid);
        }
        else if (params.containskey(algorithmname))
        {
            this.sigalgid = new algorithmidentifier(sigoid, (asn1encodable)params.get(algorithmname));
        }
        else
        {
            this.sigalgid = new algorithmidentifier(sigoid, dernull.instance);
        }

        try
        {
            asn1sequence seq = (asn1sequence)asn1primitive.frombytearray(key.getencoded());
            this.reqinfo = new certificationrequestinfo(subject, new subjectpublickeyinfo(seq), attributes);
        }
        catch (ioexception e)
        {
            throw new illegalargumentexception("can't encode public key");
        }

        signature sig;
        if (provider == null)
        {
            sig = signature.getinstance(signaturealgorithm);
        }
        else
        {
            sig = signature.getinstance(signaturealgorithm, provider);
        }

        sig.initsign(signingkey);

        try
        {
            sig.update(reqinfo.getencoded(asn1encoding.der));
        }
        catch (exception e)
        {
            throw new illegalargumentexception("exception encoding tbs cert request - " + e);
        }

        this.sigbits = new derbitstring(sig.sign());
    }

    /**
     * return the public key associated with the certification request -
     * the public key is created using the bc provider.
     */
    public publickey getpublickey()
        throws nosuchalgorithmexception, nosuchproviderexception, invalidkeyexception
    {
        return getpublickey(bouncycastleprovider.provider_name);
    }

    public publickey getpublickey(
        string  provider)
        throws nosuchalgorithmexception, nosuchproviderexception,
                invalidkeyexception
    {
        subjectpublickeyinfo    subjectpkinfo = reqinfo.getsubjectpublickeyinfo();

        
        try
        {
            x509encodedkeyspec      xspec = new x509encodedkeyspec(new derbitstring(subjectpkinfo).getbytes());
            algorithmidentifier     keyalg = subjectpkinfo.getalgorithm();
            try
            {
                if (provider == null)
                {
                    return keyfactory.getinstance(keyalg.getalgorithm().getid()).generatepublic(xspec);
                }
                else
                {
                    return keyfactory.getinstance(keyalg.getalgorithm().getid(), provider).generatepublic(xspec);
                }
            }
            catch (nosuchalgorithmexception e)
            {
                //
                // try an alternate
                //
                if (keyalgorithms.get(keyalg.getobjectid()) != null)
                {
                    string  keyalgorithm = (string)keyalgorithms.get(keyalg.getobjectid());
                    
                    if (provider == null)
                    {
                        return keyfactory.getinstance(keyalgorithm).generatepublic(xspec);
                    }
                    else
                    {
                        return keyfactory.getinstance(keyalgorithm, provider).generatepublic(xspec);
                    }
                }
                
                throw e;
            }
        }
        catch (invalidkeyspecexception e)
        {
            throw new invalidkeyexception("error decoding public key");
        }
        catch (ioexception e)
        {
            throw new invalidkeyexception("error decoding public key");
        }
    }

    /**
     * verify the request using the bc provider.
     */
    public boolean verify()
        throws nosuchalgorithmexception, nosuchproviderexception,
                invalidkeyexception, signatureexception
    {
        return verify(bouncycastleprovider.provider_name);
    }

    /**
     * verify the request using the passed in provider.
     */
    public boolean verify(
        string provider)
        throws nosuchalgorithmexception, nosuchproviderexception,
                invalidkeyexception, signatureexception
    {
        return verify(this.getpublickey(provider), provider);
    }

    /**
     * verify the request using the passed in public key and the provider..
     */
    public boolean verify(
        publickey pubkey,
        string provider)
        throws nosuchalgorithmexception, nosuchproviderexception,
                invalidkeyexception, signatureexception
    {
        signature   sig;

        try
        {
            if (provider == null)
            {
                sig = signature.getinstance(getsignaturename(sigalgid));
            }
            else
            {
                sig = signature.getinstance(getsignaturename(sigalgid), provider);
            }
        }
        catch (nosuchalgorithmexception e)
        {
            //
            // try an alternate
            //
            if (oids.get(sigalgid.getobjectid()) != null)
            {
                string  signaturealgorithm = (string)oids.get(sigalgid.getobjectid());

                if (provider == null)
                {
                    sig = signature.getinstance(signaturealgorithm);
                }
                else
                {
                    sig = signature.getinstance(signaturealgorithm, provider);
                }
            }
            else
            {
                throw e;
            }
        }

        setsignatureparameters(sig, sigalgid.getparameters());
        
        sig.initverify(pubkey);

        try
        {
            sig.update(reqinfo.getencoded(asn1encoding.der));
        }
        catch (exception e)
        {
            throw new signatureexception("exception encoding tbs cert request - " + e);
        }

        return sig.verify(sigbits.getbytes());
    }

    /**
     * return a der encoded byte array representing this object
     */
    public byte[] getencoded()
    {
        try
        {
            return this.getencoded(asn1encoding.der);
        }
        catch (ioexception e)
        {
            throw new runtimeexception(e.tostring());
        }
    }

    private void setsignatureparameters(
        signature signature,
        asn1encodable params)
        throws nosuchalgorithmexception, signatureexception, invalidkeyexception
    {
        if (params != null && !dernull.instance.equals(params))
        {
            algorithmparameters sigparams = algorithmparameters.getinstance(signature.getalgorithm(), signature.getprovider());

            try
            {
                sigparams.init(params.toasn1primitive().getencoded(asn1encoding.der));
            }
            catch (ioexception e)
            {
                throw new signatureexception("ioexception decoding parameters: " + e.getmessage());
            }

            if (signature.getalgorithm().endswith("mgf1"))
            {
                try
                {
                    signature.setparameter(sigparams.getparameterspec(pssparameterspec.class));
                }
                catch (generalsecurityexception e)
                {
                    throw new signatureexception("exception extracting parameters: " + e.getmessage());
                }
            }
        }
    }

    static string getsignaturename(
        algorithmidentifier sigalgid)
    {
        asn1encodable params = sigalgid.getparameters();

        if (params != null && !dernull.instance.equals(params))
        {
            if (sigalgid.getobjectid().equals(pkcsobjectidentifiers.id_rsassa_pss))
            {
                rsassapssparams rsaparams = rsassapssparams.getinstance(params);
                return getdigestalgname(rsaparams.gethashalgorithm().getobjectid()) + "withrsaandmgf1";
            }
        }

        return sigalgid.getobjectid().getid();
    }

    private static string getdigestalgname(
        derobjectidentifier digestalgoid)
    {
        if (pkcsobjectidentifiers.md5.equals(digestalgoid))
        {
            return "md5";
        }
        else if (oiwobjectidentifiers.idsha1.equals(digestalgoid))
        {
            return "sha1";
        }
        else if (nistobjectidentifiers.id_sha224.equals(digestalgoid))
        {
            return "sha224";
        }
        else if (nistobjectidentifiers.id_sha256.equals(digestalgoid))
        {
            return "sha256";
        }
        else if (nistobjectidentifiers.id_sha384.equals(digestalgoid))
        {
            return "sha384";
        }
        else if (nistobjectidentifiers.id_sha512.equals(digestalgoid))
        {
            return "sha512";
        }
        else if (teletrustobjectidentifiers.ripemd128.equals(digestalgoid))
        {
            return "ripemd128";
        }
        else if (teletrustobjectidentifiers.ripemd160.equals(digestalgoid))
        {
            return "ripemd160";
        }
        else if (teletrustobjectidentifiers.ripemd256.equals(digestalgoid))
        {
            return "ripemd256";
        }
        else if (cryptoproobjectidentifiers.gostr3411.equals(digestalgoid))
        {
            return "gost3411";
        }
        else
        {
            return digestalgoid.getid();            
        }
    }
}
