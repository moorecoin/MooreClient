package org.ripple.bouncycastle.jcajce.provider.util;

import java.util.hashmap;
import java.util.hashset;
import java.util.map;
import java.util.set;

import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.nist.nistobjectidentifiers;
import org.ripple.bouncycastle.asn1.oiw.oiwobjectidentifiers;
import org.ripple.bouncycastle.asn1.pkcs.pkcsobjectidentifiers;
import org.ripple.bouncycastle.crypto.digest;
import org.ripple.bouncycastle.crypto.digests.md5digest;
import org.ripple.bouncycastle.crypto.digests.sha1digest;
import org.ripple.bouncycastle.crypto.digests.sha224digest;
import org.ripple.bouncycastle.crypto.digests.sha256digest;
import org.ripple.bouncycastle.crypto.digests.sha384digest;
import org.ripple.bouncycastle.crypto.digests.sha512digest;
import org.ripple.bouncycastle.util.strings;

public class digestfactory
{
    private static set md5 = new hashset();
    private static set sha1 = new hashset();
    private static set sha224 = new hashset();
    private static set sha256 = new hashset();
    private static set sha384 = new hashset();
    private static set sha512 = new hashset();
    
    private static map oids = new hashmap();
    
    static
    {
        md5.add("md5");
        md5.add(pkcsobjectidentifiers.md5.getid());
        
        sha1.add("sha1");
        sha1.add("sha-1");
        sha1.add(oiwobjectidentifiers.idsha1.getid());
        
        sha224.add("sha224");
        sha224.add("sha-224");
        sha224.add(nistobjectidentifiers.id_sha224.getid());
        
        sha256.add("sha256");
        sha256.add("sha-256");
        sha256.add(nistobjectidentifiers.id_sha256.getid());
        
        sha384.add("sha384");
        sha384.add("sha-384");
        sha384.add(nistobjectidentifiers.id_sha384.getid());
        
        sha512.add("sha512");
        sha512.add("sha-512");
        sha512.add(nistobjectidentifiers.id_sha512.getid()); 

        oids.put("md5", pkcsobjectidentifiers.md5);
        oids.put(pkcsobjectidentifiers.md5.getid(), pkcsobjectidentifiers.md5);
        
        oids.put("sha1", oiwobjectidentifiers.idsha1);
        oids.put("sha-1", oiwobjectidentifiers.idsha1);
        oids.put(oiwobjectidentifiers.idsha1.getid(), oiwobjectidentifiers.idsha1);
        
        oids.put("sha224", nistobjectidentifiers.id_sha224);
        oids.put("sha-224", nistobjectidentifiers.id_sha224);
        oids.put(nistobjectidentifiers.id_sha224.getid(), nistobjectidentifiers.id_sha224);
        
        oids.put("sha256", nistobjectidentifiers.id_sha256);
        oids.put("sha-256", nistobjectidentifiers.id_sha256);
        oids.put(nistobjectidentifiers.id_sha256.getid(), nistobjectidentifiers.id_sha256);
        
        oids.put("sha384", nistobjectidentifiers.id_sha384);
        oids.put("sha-384", nistobjectidentifiers.id_sha384);
        oids.put(nistobjectidentifiers.id_sha384.getid(), nistobjectidentifiers.id_sha384);
        
        oids.put("sha512", nistobjectidentifiers.id_sha512);
        oids.put("sha-512", nistobjectidentifiers.id_sha512);
        oids.put(nistobjectidentifiers.id_sha512.getid(), nistobjectidentifiers.id_sha512); 
    }
    
    public static digest getdigest(
        string digestname) 
    {
        digestname = strings.touppercase(digestname);
        
        if (sha1.contains(digestname))
        {
            return new sha1digest();
        }
        if (md5.contains(digestname))
        {
            return new md5digest();
        }
        if (sha224.contains(digestname))
        {
            return new sha224digest();
        }
        if (sha256.contains(digestname))
        {
            return new sha256digest();
        }
        if (sha384.contains(digestname))
        {
            return new sha384digest();
        }
        if (sha512.contains(digestname))
        {
            return new sha512digest();
        }
        
        return null;
    }
    
    public static boolean issamedigest(
        string digest1,
        string digest2)
    {
        return (sha1.contains(digest1) && sha1.contains(digest2))
            || (sha224.contains(digest1) && sha224.contains(digest2))
            || (sha256.contains(digest1) && sha256.contains(digest2))
            || (sha384.contains(digest1) && sha384.contains(digest2))
            || (sha512.contains(digest1) && sha512.contains(digest2))
            || (md5.contains(digest1) && md5.contains(digest2));
    }
    
    public static asn1objectidentifier getoid(
        string digestname)
    {
        return (asn1objectidentifier)oids.get(digestname);
    }
}
