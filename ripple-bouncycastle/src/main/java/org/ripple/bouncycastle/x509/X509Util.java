package org.ripple.bouncycastle.x509;

import java.io.ioexception;
import java.security.invalidkeyexception;
import java.security.nosuchalgorithmexception;
import java.security.nosuchproviderexception;
import java.security.privatekey;
import java.security.provider;
import java.security.securerandom;
import java.security.security;
import java.security.signature;
import java.security.signatureexception;
import java.util.arraylist;
import java.util.enumeration;
import java.util.hashset;
import java.util.hashtable;
import java.util.iterator;
import java.util.list;
import java.util.set;

import javax.security.auth.x500.x500principal;

import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1encoding;
import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.dernull;
import org.ripple.bouncycastle.asn1.derobjectidentifier;
import org.ripple.bouncycastle.asn1.cryptopro.cryptoproobjectidentifiers;
import org.ripple.bouncycastle.asn1.nist.nistobjectidentifiers;
import org.ripple.bouncycastle.asn1.oiw.oiwobjectidentifiers;
import org.ripple.bouncycastle.asn1.pkcs.pkcsobjectidentifiers;
import org.ripple.bouncycastle.asn1.pkcs.rsassapssparams;
import org.ripple.bouncycastle.asn1.teletrust.teletrustobjectidentifiers;
import org.ripple.bouncycastle.asn1.x509.algorithmidentifier;
import org.ripple.bouncycastle.asn1.x9.x9objectidentifiers;
import org.ripple.bouncycastle.jce.x509principal;
import org.ripple.bouncycastle.util.strings;

class x509util
{
    private static hashtable algorithms = new hashtable();
    private static hashtable params = new hashtable();
    private static set       noparams = new hashset();
    
    static
    {   
        algorithms.put("md2withrsaencryption", pkcsobjectidentifiers.md2withrsaencryption);
        algorithms.put("md2withrsa", pkcsobjectidentifiers.md2withrsaencryption);
        algorithms.put("md5withrsaencryption", pkcsobjectidentifiers.md5withrsaencryption);
        algorithms.put("md5withrsa", pkcsobjectidentifiers.md5withrsaencryption);
        algorithms.put("sha1withrsaencryption", pkcsobjectidentifiers.sha1withrsaencryption);
        algorithms.put("sha1withrsa", pkcsobjectidentifiers.sha1withrsaencryption);
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
        algorithms.put("ripemd160withrsaencryption", teletrustobjectidentifiers.rsasignaturewithripemd160);
        algorithms.put("ripemd160withrsa", teletrustobjectidentifiers.rsasignaturewithripemd160);
        algorithms.put("ripemd128withrsaencryption", teletrustobjectidentifiers.rsasignaturewithripemd128);
        algorithms.put("ripemd128withrsa", teletrustobjectidentifiers.rsasignaturewithripemd128);
        algorithms.put("ripemd256withrsaencryption", teletrustobjectidentifiers.rsasignaturewithripemd256);
        algorithms.put("ripemd256withrsa", teletrustobjectidentifiers.rsasignaturewithripemd256);
        algorithms.put("sha1withdsa", x9objectidentifiers.id_dsa_with_sha1);
        algorithms.put("dsawithsha1", x9objectidentifiers.id_dsa_with_sha1);
        algorithms.put("sha224withdsa", nistobjectidentifiers.dsa_with_sha224);
        algorithms.put("sha256withdsa", nistobjectidentifiers.dsa_with_sha256);
        algorithms.put("sha384withdsa", nistobjectidentifiers.dsa_with_sha384);
        algorithms.put("sha512withdsa", nistobjectidentifiers.dsa_with_sha512);
        algorithms.put("sha1withecdsa", x9objectidentifiers.ecdsa_with_sha1);
        algorithms.put("ecdsawithsha1", x9objectidentifiers.ecdsa_with_sha1);
        algorithms.put("sha224withecdsa", x9objectidentifiers.ecdsa_with_sha224);
        algorithms.put("sha256withecdsa", x9objectidentifiers.ecdsa_with_sha256);
        algorithms.put("sha384withecdsa", x9objectidentifiers.ecdsa_with_sha384);
        algorithms.put("sha512withecdsa", x9objectidentifiers.ecdsa_with_sha512);
        algorithms.put("gost3411withgost3410", cryptoproobjectidentifiers.gostr3411_94_with_gostr3410_94);
        algorithms.put("gost3411withgost3410-94", cryptoproobjectidentifiers.gostr3411_94_with_gostr3410_94);
        algorithms.put("gost3411withecgost3410", cryptoproobjectidentifiers.gostr3411_94_with_gostr3410_2001);
        algorithms.put("gost3411withecgost3410-2001", cryptoproobjectidentifiers.gostr3411_94_with_gostr3410_2001);
        algorithms.put("gost3411withgost3410-2001", cryptoproobjectidentifiers.gostr3411_94_with_gostr3410_2001);

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
        noparams.add(nistobjectidentifiers.dsa_with_sha384);
        noparams.add(nistobjectidentifiers.dsa_with_sha512);
        
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

    static derobjectidentifier getalgorithmoid(
        string algorithmname)
    {
        algorithmname = strings.touppercase(algorithmname);
        
        if (algorithms.containskey(algorithmname))
        {
            return (derobjectidentifier)algorithms.get(algorithmname);
        }
        
        return new derobjectidentifier(algorithmname);
    }
    
    static algorithmidentifier getsigalgid(
        derobjectidentifier sigoid,
        string              algorithmname)
    {
        if (noparams.contains(sigoid))
        {
            return new algorithmidentifier(sigoid);
        }

        algorithmname = strings.touppercase(algorithmname);

        if (params.containskey(algorithmname))
        {
            return new algorithmidentifier(sigoid, (asn1encodable)params.get(algorithmname));
        }
        else
        {
            return new algorithmidentifier(sigoid, dernull.instance);
        }
    }
    
    static iterator getalgnames()
    {
        enumeration e = algorithms.keys();
        list        l = new arraylist();
        
        while (e.hasmoreelements())
        {
            l.add(e.nextelement());
        }
        
        return l.iterator();
    }

    static signature getsignatureinstance(
        string algorithm)
        throws nosuchalgorithmexception
    {
        return signature.getinstance(algorithm);
    }

    static signature getsignatureinstance(
        string algorithm,
        string provider)
        throws nosuchproviderexception, nosuchalgorithmexception
    {
        if (provider != null)
        {
            return signature.getinstance(algorithm, provider);
        }
        else
        {
            return signature.getinstance(algorithm);
        }
    }

    static byte[] calculatesignature(
        derobjectidentifier sigoid,
        string              signame,
        privatekey          key,
        securerandom        random,
        asn1encodable       object)
        throws ioexception, nosuchalgorithmexception, invalidkeyexception, signatureexception
    {
        signature sig;

        if (sigoid == null)
        {
            throw new illegalstateexception("no signature algorithm specified");
        }

        sig = x509util.getsignatureinstance(signame);

        if (random != null)
        {
            sig.initsign(key, random);
        }
        else
        {
            sig.initsign(key);
        }

        sig.update(object.toasn1primitive().getencoded(asn1encoding.der));

        return sig.sign();
    }

    static byte[] calculatesignature(
        derobjectidentifier sigoid,
        string              signame,
        string              provider,
        privatekey          key,
        securerandom        random,
        asn1encodable       object)
        throws ioexception, nosuchproviderexception, nosuchalgorithmexception, invalidkeyexception, signatureexception
    {
        signature sig;

        if (sigoid == null)
        {
            throw new illegalstateexception("no signature algorithm specified");
        }

        sig = x509util.getsignatureinstance(signame, provider);

        if (random != null)
        {
            sig.initsign(key, random);
        }
        else
        {
            sig.initsign(key);
        }

        sig.update(object.toasn1primitive().getencoded(asn1encoding.der));

        return sig.sign();
    }

    static x509principal convertprincipal(
        x500principal principal)
    {
        try
        {
            return new x509principal(principal.getencoded());
        }
        catch (ioexception e)
        {
            throw new illegalargumentexception("cannot convert principal");
        }
    }

    static class implementation
    {
        object      engine;
        provider provider;

        implementation(
            object      engine,
            provider    provider)
        {
            this.engine = engine;
            this.provider = provider;
        }

        object getengine()
        {
            return engine;
        }

        provider getprovider()
        {
            return provider;
        }
    }

    /**
     * see if we can find an algorithm (or its alias and what it represents) in
     * the property table for the given provider.
     */
    static implementation getimplementation(
        string      basename,
        string      algorithm,
        provider    prov)
        throws nosuchalgorithmexception
    {
        algorithm = strings.touppercase(algorithm);

        string      alias;

        while ((alias = prov.getproperty("alg.alias." + basename + "." + algorithm)) != null)
        {
            algorithm = alias;
        }

        string      classname = prov.getproperty(basename + "." + algorithm);

        if (classname != null)
        {
            try
            {
                class       cls;
                classloader clsloader = prov.getclass().getclassloader();

                if (clsloader != null)
                {
                    cls = clsloader.loadclass(classname);
                }
                else
                {
                    cls = class.forname(classname);
                }

                return new implementation(cls.newinstance(), prov);
            }
            catch (classnotfoundexception e)
            {
                throw new illegalstateexception(
                    "algorithm " + algorithm + " in provider " + prov.getname() + " but no class \"" + classname + "\" found!");
            }
            catch (exception e)
            {
                throw new illegalstateexception(
                    "algorithm " + algorithm + " in provider " + prov.getname() + " but class \"" + classname + "\" inaccessible!");
            }
        }

        throw new nosuchalgorithmexception("cannot find implementation " + algorithm + " for provider " + prov.getname());
    }

    /**
     * return an implementation for a given algorithm/provider.
     * if the provider is null, we grab the first avalaible who has the required algorithm.
     */
    static implementation getimplementation(
        string      basename,
        string      algorithm)
        throws nosuchalgorithmexception
    {
        provider[] prov = security.getproviders();

        //
        // search every provider looking for the algorithm we want.
        //
        for (int i = 0; i != prov.length; i++)
        {
            //
            // try case insensitive
            //
            implementation imp = getimplementation(basename, strings.touppercase(algorithm), prov[i]);
            if (imp != null)
            {
                return imp;
            }

            try
            {
                imp = getimplementation(basename, algorithm, prov[i]);
            }
            catch (nosuchalgorithmexception e)
            {
                // continue
            }
        }

        throw new nosuchalgorithmexception("cannot find implementation " + algorithm);
    }

    static provider getprovider(string provider)
        throws nosuchproviderexception
    {
        provider prov = security.getprovider(provider);

        if (prov == null)
        {
            throw new nosuchproviderexception("provider " + provider + " not found");
        }

        return prov;
    }
}
