package org.ripple.bouncycastle.ocsp;

import org.ripple.bouncycastle.asn1.dernull;
import org.ripple.bouncycastle.asn1.derobjectidentifier;
import org.ripple.bouncycastle.asn1.cryptopro.cryptoproobjectidentifiers;
import org.ripple.bouncycastle.asn1.nist.nistobjectidentifiers;
import org.ripple.bouncycastle.asn1.pkcs.pkcsobjectidentifiers;
import org.ripple.bouncycastle.asn1.teletrust.teletrustobjectidentifiers;
import org.ripple.bouncycastle.asn1.x509.algorithmidentifier;
import org.ripple.bouncycastle.asn1.x9.x9objectidentifiers;
import org.ripple.bouncycastle.util.strings;

import java.security.invalidalgorithmparameterexception;
import java.security.messagedigest;
import java.security.nosuchalgorithmexception;
import java.security.nosuchproviderexception;
import java.security.signature;
import java.security.cert.certstore;
import java.security.cert.certstoreparameters;
import java.security.cert.certificateexception;
import java.security.cert.certificatefactory;
import java.util.arraylist;
import java.util.enumeration;
import java.util.hashset;
import java.util.hashtable;
import java.util.iterator;
import java.util.list;
import java.util.set;

class ocsputil
{
    private static hashtable algorithms = new hashtable();
    private static hashtable oids = new hashtable();
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
        algorithms.put("sha1withecdsa", x9objectidentifiers.ecdsa_with_sha1);
        algorithms.put("ecdsawithsha1", x9objectidentifiers.ecdsa_with_sha1);
        algorithms.put("sha224withecdsa", x9objectidentifiers.ecdsa_with_sha224);
        algorithms.put("sha256withecdsa", x9objectidentifiers.ecdsa_with_sha256);
        algorithms.put("sha384withecdsa", x9objectidentifiers.ecdsa_with_sha384);
        algorithms.put("sha512withecdsa", x9objectidentifiers.ecdsa_with_sha512);
        algorithms.put("gost3411withgost3410", cryptoproobjectidentifiers.gostr3411_94_with_gostr3410_94);
        algorithms.put("gost3411withgost3410-94", cryptoproobjectidentifiers.gostr3411_94_with_gostr3410_94);

        oids.put(pkcsobjectidentifiers.md2withrsaencryption, "md2withrsa");
        oids.put(pkcsobjectidentifiers.md5withrsaencryption, "md5withrsa");
        oids.put(pkcsobjectidentifiers.sha1withrsaencryption, "sha1withrsa");
        oids.put(pkcsobjectidentifiers.sha224withrsaencryption, "sha224withrsa");
        oids.put(pkcsobjectidentifiers.sha256withrsaencryption, "sha256withrsa");
        oids.put(pkcsobjectidentifiers.sha384withrsaencryption, "sha384withrsa");
        oids.put(pkcsobjectidentifiers.sha512withrsaencryption, "sha512withrsa");
        oids.put(teletrustobjectidentifiers.rsasignaturewithripemd160, "ripemd160withrsa");
        oids.put(teletrustobjectidentifiers.rsasignaturewithripemd128, "ripemd128withrsa");
        oids.put(teletrustobjectidentifiers.rsasignaturewithripemd256, "ripemd256withrsa");
        oids.put(x9objectidentifiers.id_dsa_with_sha1, "sha1withdsa");
        oids.put(nistobjectidentifiers.dsa_with_sha224, "sha224withdsa");
        oids.put(nistobjectidentifiers.dsa_with_sha256, "sha256withdsa");
        oids.put(x9objectidentifiers.ecdsa_with_sha1, "sha1withecdsa");
        oids.put(x9objectidentifiers.ecdsa_with_sha224, "sha224withecdsa");
        oids.put(x9objectidentifiers.ecdsa_with_sha256, "sha256withecdsa");
        oids.put(x9objectidentifiers.ecdsa_with_sha384, "sha384withecdsa");
        oids.put(x9objectidentifiers.ecdsa_with_sha512, "sha512withecdsa");
        oids.put(cryptoproobjectidentifiers.gostr3411_94_with_gostr3410_94, "gost3411withgost3410");

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

    static string getalgorithmname(
        derobjectidentifier oid)
    {
        if (oids.containskey(oid))
        {
            return (string)oids.get(oid);
        }
        
        return oid.getid();
    }
    
    static algorithmidentifier getsigalgid(
        derobjectidentifier sigoid)
    {
        if (noparams.contains(sigoid))
        {
            return new algorithmidentifier(sigoid);
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

    static certstore createcertstoreinstance(string type, certstoreparameters params, string provider)
        throws invalidalgorithmparameterexception, nosuchalgorithmexception, nosuchproviderexception
    {
        if (provider == null)
        {
            return certstore.getinstance(type, params);
        }

        return certstore.getinstance(type, params, provider);
    }

    static messagedigest createdigestinstance(string digestname, string provider)
        throws nosuchalgorithmexception, nosuchproviderexception
    {
        if (provider == null)
        {
            return messagedigest.getinstance(digestname);
        }

        return messagedigest.getinstance(digestname, provider);
    }

    static signature createsignatureinstance(string signame, string provider)
        throws nosuchalgorithmexception, nosuchproviderexception
    {
        if (provider == null)
        {
            return signature.getinstance(signame);
        }

        return signature.getinstance(signame, provider);
    }

    static certificatefactory createx509certificatefactory(string provider)
        throws certificateexception, nosuchproviderexception
    {
        if (provider == null)
        {
            return certificatefactory.getinstance("x.509");
        }

        return certificatefactory.getinstance("x.509", provider);
    }
}
