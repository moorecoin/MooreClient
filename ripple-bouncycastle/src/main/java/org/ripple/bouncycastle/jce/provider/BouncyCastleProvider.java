package org.ripple.bouncycastle.jce.provider;

import java.io.ioexception;
import java.security.accesscontroller;
import java.security.privatekey;
import java.security.privilegedaction;
import java.security.provider;
import java.security.publickey;
import java.util.hashmap;
import java.util.map;

import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.pkcs.privatekeyinfo;
import org.ripple.bouncycastle.asn1.x509.subjectpublickeyinfo;
import org.ripple.bouncycastle.jcajce.provider.config.configurableprovider;
import org.ripple.bouncycastle.jcajce.provider.config.providerconfiguration;
import org.ripple.bouncycastle.jcajce.provider.util.algorithmprovider;
import org.ripple.bouncycastle.jcajce.provider.util.asymmetrickeyinfoconverter;

/**
 * to add the provider at runtime use:
 * <pre>
 * import java.security.security;
 * import org.ripple.bouncycastle.jce.provider.bouncycastleprovider;
 *
 * security.addprovider(new bouncycastleprovider());
 * </pre>
 * the provider can also be configured as part of your environment via
 * static registration by adding an entry to the java.security properties
 * file (found in $java_home/jre/lib/security/java.security, where
 * $java_home is the location of your jdk/jre distribution). you'll find
 * detailed instructions in the file but basically it comes down to adding
 * a line:
 * <pre>
 * <code>
 *    security.provider.&lt;n&gt;=org.ripple.bouncycastle.jce.provider.bouncycastleprovider
 * </code>
 * </pre>
 * where &lt;n&gt; is the preference you want the provider at (1 being the
 * most preferred).
 * <p>note: jce algorithm names should be upper-case only so the case insensitive
 * test for getinstance works.
 */
public final class bouncycastleprovider extends provider
    implements configurableprovider
{
    private static string info = "bouncycastle security provider v1.49";

    public static final string provider_name = "rbc";

    public static final providerconfiguration configuration = new bouncycastleproviderconfiguration();

    private static final map keyinfoconverters = new hashmap();

    /*
     * configurable symmetric ciphers
     */
    private static final string symmetric_package = "org.ripple.bouncycastle.jcajce.provider.symmetric.";

    private static final string[] symmetric_generic =
    {
        "pbepbkdf2", "pbepkcs12"
    };

    private static final string[] symmetric_macs =
    {
        "siphash"
    };

    private static final string[] symmetric_ciphers =
    {
        "aes", "arc4", "blowfish", "camellia", "cast5", "cast6", "des", "desede", "gost28147", "grainv1", "grain128", "hc128", "hc256", "idea",
        "noekeon", "rc2", "rc5", "rc6", "rijndael", "salsa20", "seed", "serpent", "skipjack", "tea", "twofish", "vmpc", "vmpcksa3", "xtea"
    };

     /*
     * configurable asymmetric ciphers
     */
    private static final string asymmetric_package = "org.ripple.bouncycastle.jcajce.provider.asymmetric.";

    // this one is required for gnu class path - it needs to be loaded first as the
    // later ones configure it.
    private static final string[] asymmetric_generic =
    {
        "x509", "ies"
    };

    private static final string[] asymmetric_ciphers =
    {
        "dsa", "dh", "ec", "rsa", "gost", "ecgost", "elgamal", "dstu4145"
    };

    /*
     * configurable digests
     */
    private static final string digest_package = "org.ripple.bouncycastle.jcajce.provider.digest.";
    private static final string[] digests =
    {
        "gost3411", "md2", "md4", "md5", "sha1", "ripemd128", "ripemd160", "ripemd256", "ripemd320", "sha224", "sha256", "sha384", "sha512", "sha3", "tiger", "whirlpool"
    };

    /*
     * configurable digests
     */
    private static final string keystore_package = "org.ripple.bouncycastle.jcajce.provider.keystore.";
    private static final string[] keystores =
    {
        "bc", "pkcs12"
    };

    /**
     * construct a new provider.  this should only be required when
     * using runtime registration of the provider using the
     * <code>security.addprovider()</code> mechanism.
     */
    public bouncycastleprovider()
    {
        super(provider_name, 1.49, info);

        accesscontroller.doprivileged(new privilegedaction()
        {
            public object run()
            {
                setup();
                return null;
            }
        });
    }

    private void setup()
    {
        loadalgorithms(digest_package, digests);

        loadalgorithms(symmetric_package, symmetric_generic);

        loadalgorithms(symmetric_package, symmetric_macs);

        loadalgorithms(symmetric_package, symmetric_ciphers);

        loadalgorithms(asymmetric_package, asymmetric_generic);

        loadalgorithms(asymmetric_package, asymmetric_ciphers);

        loadalgorithms(keystore_package, keystores);

        //
        // x509store
        //
        put("x509store.certificate/collection", "org.ripple.bouncycastle.jce.provider.x509storecertcollection");
        put("x509store.attributecertificate/collection", "org.ripple.bouncycastle.jce.provider.x509storeattrcertcollection");
        put("x509store.crl/collection", "org.ripple.bouncycastle.jce.provider.x509storecrlcollection");
        put("x509store.certificatepair/collection", "org.ripple.bouncycastle.jce.provider.x509storecertpaircollection");

        put("x509store.certificate/ldap", "org.ripple.bouncycastle.jce.provider.x509storeldapcerts");
        put("x509store.crl/ldap", "org.ripple.bouncycastle.jce.provider.x509storeldapcrls");
        put("x509store.attributecertificate/ldap", "org.ripple.bouncycastle.jce.provider.x509storeldapattrcerts");
        put("x509store.certificatepair/ldap", "org.ripple.bouncycastle.jce.provider.x509storeldapcertpairs");
        
        //
        // x509streamparser
        //
        put("x509streamparser.certificate", "org.ripple.bouncycastle.jce.provider.x509certparser");
        put("x509streamparser.attributecertificate", "org.ripple.bouncycastle.jce.provider.x509attrcertparser");
        put("x509streamparser.crl", "org.ripple.bouncycastle.jce.provider.x509crlparser");
        put("x509streamparser.certificatepair", "org.ripple.bouncycastle.jce.provider.x509certpairparser");

        //
        // cipher engines
        //
        put("cipher.brokenpbewithmd5anddes", "org.ripple.bouncycastle.jce.provider.brokenjceblockcipher$brokepbewithmd5anddes");

        put("cipher.brokenpbewithsha1anddes", "org.ripple.bouncycastle.jce.provider.brokenjceblockcipher$brokepbewithsha1anddes");


        put("cipher.oldpbewithshaandtwofish-cbc", "org.ripple.bouncycastle.jce.provider.brokenjceblockcipher$oldpbewithshaandtwofish");

        // certification path api
        put("certpathvalidator.rfc3281", "org.ripple.bouncycastle.jce.provider.pkixattrcertpathvalidatorspi");
        put("certpathbuilder.rfc3281", "org.ripple.bouncycastle.jce.provider.pkixattrcertpathbuilderspi");
        put("certpathvalidator.rfc3280", "org.ripple.bouncycastle.jce.provider.pkixcertpathvalidatorspi");
        put("certpathbuilder.rfc3280", "org.ripple.bouncycastle.jce.provider.pkixcertpathbuilderspi");
        put("certpathvalidator.pkix", "org.ripple.bouncycastle.jce.provider.pkixcertpathvalidatorspi");
        put("certpathbuilder.pkix", "org.ripple.bouncycastle.jce.provider.pkixcertpathbuilderspi");
        put("certstore.collection", "org.ripple.bouncycastle.jce.provider.certstorecollectionspi");
        put("certstore.ldap", "org.ripple.bouncycastle.jce.provider.x509ldapcertstorespi");
        put("certstore.multi", "org.ripple.bouncycastle.jce.provider.multicertstorespi");
        put("alg.alias.certstore.x509ldap", "ldap");
    }

    private void loadalgorithms(string packagename, string[] names)
    {
        for (int i = 0; i != names.length; i++)
        {
            class clazz = null;
            try
            {
                classloader loader = this.getclass().getclassloader();

                if (loader != null)
                {
                    clazz = loader.loadclass(packagename + names[i] + "$mappings");
                }
                else
                {
                    clazz = class.forname(packagename + names[i] + "$mappings");
                }
            }
            catch (classnotfoundexception e)
            {
                // ignore
            }

            if (clazz != null)
            {
                try
                {
                    ((algorithmprovider)clazz.newinstance()).configure(this);
                }
                catch (exception e)
                {   // this should never ever happen!!
                    throw new internalerror("cannot create instance of "
                        + packagename + names[i] + "$mappings : " + e);
                }
            }
        }
    }

    public void setparameter(string parametername, object parameter)
    {
        synchronized (configuration)
        {
            ((bouncycastleproviderconfiguration)configuration).setparameter(parametername, parameter);
        }
    }

    public boolean hasalgorithm(string type, string name)
    {
        return containskey(type + "." + name) || containskey("alg.alias." + type + "." + name);
    }

    public void addalgorithm(string key, string value)
    {
        if (containskey(key))
        {
            throw new illegalstateexception("duplicate provider key (" + key + ") found");
        }

        put(key, value);
    }

    public void addkeyinfoconverter(asn1objectidentifier oid, asymmetrickeyinfoconverter keyinfoconverter)
    {
        keyinfoconverters.put(oid, keyinfoconverter);
    }

    public static publickey getpublickey(subjectpublickeyinfo publickeyinfo)
        throws ioexception
    {
        asymmetrickeyinfoconverter converter = (asymmetrickeyinfoconverter)keyinfoconverters.get(publickeyinfo.getalgorithm().getalgorithm());

        if (converter == null)
        {
            return null;
        }

        return converter.generatepublic(publickeyinfo);
    }

    public static privatekey getprivatekey(privatekeyinfo privatekeyinfo)
        throws ioexception
    {
        asymmetrickeyinfoconverter converter = (asymmetrickeyinfoconverter)keyinfoconverters.get(privatekeyinfo.getprivatekeyalgorithm().getalgorithm());

        if (converter == null)
        {
            return null;
        }

        return converter.generateprivate(privatekeyinfo);
    }
}
