package org.ripple.bouncycastle.jcajce.provider.symmetric;

import java.security.algorithmparameters;
import java.security.invalidalgorithmparameterexception;
import java.security.securerandom;
import java.security.spec.algorithmparameterspec;

import javax.crypto.spec.ivparameterspec;

import org.ripple.bouncycastle.asn1.bc.bcobjectidentifiers;
import org.ripple.bouncycastle.asn1.nist.nistobjectidentifiers;
import org.ripple.bouncycastle.crypto.blockcipher;
import org.ripple.bouncycastle.crypto.bufferedblockcipher;
import org.ripple.bouncycastle.crypto.cipherkeygenerator;
import org.ripple.bouncycastle.crypto.engines.aesfastengine;
import org.ripple.bouncycastle.crypto.engines.aeswrapengine;
import org.ripple.bouncycastle.crypto.engines.rfc3211wrapengine;
import org.ripple.bouncycastle.crypto.macs.cmac;
import org.ripple.bouncycastle.crypto.macs.gmac;
import org.ripple.bouncycastle.crypto.modes.cbcblockcipher;
import org.ripple.bouncycastle.crypto.modes.cfbblockcipher;
import org.ripple.bouncycastle.crypto.modes.gcmblockcipher;
import org.ripple.bouncycastle.crypto.modes.ofbblockcipher;
import org.ripple.bouncycastle.jcajce.provider.config.configurableprovider;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.basealgorithmparametergenerator;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.baseblockcipher;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.basekeygenerator;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.basemac;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.basewrapcipher;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.blockcipherprovider;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.ivalgorithmparameters;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.pbesecretkeyfactory;
import org.ripple.bouncycastle.jce.provider.bouncycastleprovider;

public final class aes
{
    private aes()
    {
    }
    
    public static class ecb
        extends baseblockcipher
    {
        public ecb()
        {
            super(new blockcipherprovider()
            {
                public blockcipher get()
                {
                    return new aesfastengine();
                }
            });
        }
    }

    public static class cbc
       extends baseblockcipher
    {
        public cbc()
        {
            super(new cbcblockcipher(new aesfastengine()), 128);
        }
    }

    static public class cfb
        extends baseblockcipher
    {
        public cfb()
        {
            super(new bufferedblockcipher(new cfbblockcipher(new aesfastengine(), 128)), 128);
        }
    }

    static public class ofb
        extends baseblockcipher
    {
        public ofb()
        {
            super(new bufferedblockcipher(new ofbblockcipher(new aesfastengine(), 128)), 128);
        }
    }

    public static class aescmac
        extends basemac
    {
        public aescmac()
        {
            super(new cmac(new aesfastengine()));
        }
    }

    public static class aesgmac
        extends basemac
    {
        public aesgmac()
        {
            super(new gmac(new gcmblockcipher(new aesfastengine())));
        }
    }

    static public class wrap
        extends basewrapcipher
    {
        public wrap()
        {
            super(new aeswrapengine());
        }
    }

    public static class rfc3211wrap
        extends basewrapcipher
    {
        public rfc3211wrap()
        {
            super(new rfc3211wrapengine(new aesfastengine()), 16);
        }
    }

    
    /**
     * pbewithaes-cbc
     */
    static public class pbewithaescbc
        extends baseblockcipher
    {
        public pbewithaescbc()
        {
            super(new cbcblockcipher(new aesfastengine()));
        }
    }
    
    public static class keygen
        extends basekeygenerator
    {
        public keygen()
        {
            this(192);
        }

        public keygen(int keysize)
        {
            super("aes", keysize, new cipherkeygenerator());
        }
    }

    public static class keygen128
        extends keygen
    {
        public keygen128()
        {
            super(128);
        }
    }

    public static class keygen192
        extends keygen
    {
        public keygen192()
        {
            super(192);
        }
    }

    public static class keygen256
        extends keygen
    {
        public keygen256()
        {
            super(256);
        }
    }
    
    /**
     * pbewithsha1and128bitaes-bc
     */
    static public class pbewithshaand128bitaesbc
        extends pbesecretkeyfactory
    {
        public pbewithshaand128bitaesbc()
        {
            super("pbewithsha1and128bitaes-cbc-bc", null, true, pkcs12, sha1, 128, 128);
        }
    }
    
    /**
     * pbewithsha1and192bitaes-bc
     */
    static public class pbewithshaand192bitaesbc
        extends pbesecretkeyfactory
    {
        public pbewithshaand192bitaesbc()
        {
            super("pbewithsha1and192bitaes-cbc-bc", null, true, pkcs12, sha1, 192, 128);
        }
    }
    
    /**
     * pbewithsha1and256bitaes-bc
     */
    static public class pbewithshaand256bitaesbc
        extends pbesecretkeyfactory
    {
        public pbewithshaand256bitaesbc()
        {
            super("pbewithsha1and256bitaes-cbc-bc", null, true, pkcs12, sha1, 256, 128);
        }
    }
    
    /**
     * pbewithsha256and128bitaes-bc
     */
    static public class pbewithsha256and128bitaesbc
        extends pbesecretkeyfactory
    {
        public pbewithsha256and128bitaesbc()
        {
            super("pbewithsha256and128bitaes-cbc-bc", null, true, pkcs12, sha256, 128, 128);
        }
    }
    
    /**
     * pbewithsha256and192bitaes-bc
     */
    static public class pbewithsha256and192bitaesbc
        extends pbesecretkeyfactory
    {
        public pbewithsha256and192bitaesbc()
        {
            super("pbewithsha256and192bitaes-cbc-bc", null, true, pkcs12, sha256, 192, 128);
        }
    }
    
    /**
     * pbewithsha256and256bitaes-bc
     */
    static public class pbewithsha256and256bitaesbc
        extends pbesecretkeyfactory
    {
        public pbewithsha256and256bitaesbc()
        {
            super("pbewithsha256and256bitaes-cbc-bc", null, true, pkcs12, sha256, 256, 128);
        }
    }
    
    /**
     * pbewithmd5and128bitaes-openssl
     */
    static public class pbewithmd5and128bitaescbcopenssl
        extends pbesecretkeyfactory
    {
        public pbewithmd5and128bitaescbcopenssl()
        {
            super("pbewithmd5and128bitaes-cbc-openssl", null, true, openssl, md5, 128, 128);
        }
    }
    
    /**
     * pbewithmd5and192bitaes-openssl
     */
    static public class pbewithmd5and192bitaescbcopenssl
        extends pbesecretkeyfactory
    {
        public pbewithmd5and192bitaescbcopenssl()
        {
            super("pbewithmd5and192bitaes-cbc-openssl", null, true, openssl, md5, 192, 128);
        }
    }
    
    /**
     * pbewithmd5and256bitaes-openssl
     */
    static public class pbewithmd5and256bitaescbcopenssl
        extends pbesecretkeyfactory
    {
        public pbewithmd5and256bitaescbcopenssl()
        {
            super("pbewithmd5and256bitaes-cbc-openssl", null, true, openssl, md5, 256, 128);
        }
    }
    
    public static class algparamgen
        extends basealgorithmparametergenerator
    {
        protected void engineinit(
            algorithmparameterspec genparamspec,
            securerandom random)
            throws invalidalgorithmparameterexception
        {
            throw new invalidalgorithmparameterexception("no supported algorithmparameterspec for aes parameter generation.");
        }

        protected algorithmparameters enginegenerateparameters()
        {
            byte[]  iv = new byte[16];

            if (random == null)
            {
                random = new securerandom();
            }

            random.nextbytes(iv);

            algorithmparameters params;

            try
            {
                params = algorithmparameters.getinstance("aes", bouncycastleprovider.provider_name);
                params.init(new ivparameterspec(iv));
            }
            catch (exception e)
            {
                throw new runtimeexception(e.getmessage());
            }

            return params;
        }
    }

    public static class algparams
        extends ivalgorithmparameters
    {
        protected string enginetostring()
        {
            return "aes iv";
        }
    }

    public static class mappings
        extends symmetricalgorithmprovider
    {
        private static final string prefix = aes.class.getname();
        
        /**
         * these three got introduced in some messages as a result of a typo in an
         * early document. we don't produce anything using these oid values, but we'll
         * read them.
         */
        private static final string wrongaes128 = "2.16.840.1.101.3.4.2";
        private static final string wrongaes192 = "2.16.840.1.101.3.4.22";
        private static final string wrongaes256 = "2.16.840.1.101.3.4.42";

        public mappings()
        {
        }

        public void configure(configurableprovider provider)
        {
            provider.addalgorithm("algorithmparameters.aes", prefix + "$algparams");
            provider.addalgorithm("alg.alias.algorithmparameters." + wrongaes128, "aes");
            provider.addalgorithm("alg.alias.algorithmparameters." + wrongaes192, "aes");
            provider.addalgorithm("alg.alias.algorithmparameters." + wrongaes256, "aes");
            provider.addalgorithm("alg.alias.algorithmparameters." + nistobjectidentifiers.id_aes128_cbc, "aes");
            provider.addalgorithm("alg.alias.algorithmparameters." + nistobjectidentifiers.id_aes192_cbc, "aes");
            provider.addalgorithm("alg.alias.algorithmparameters." + nistobjectidentifiers.id_aes256_cbc, "aes");

            provider.addalgorithm("algorithmparametergenerator.aes", prefix + "$algparamgen");
            provider.addalgorithm("alg.alias.algorithmparametergenerator." + wrongaes128, "aes");
            provider.addalgorithm("alg.alias.algorithmparametergenerator." + wrongaes192, "aes");
            provider.addalgorithm("alg.alias.algorithmparametergenerator." + wrongaes256, "aes");
            provider.addalgorithm("alg.alias.algorithmparametergenerator." + nistobjectidentifiers.id_aes128_cbc, "aes");
            provider.addalgorithm("alg.alias.algorithmparametergenerator." + nistobjectidentifiers.id_aes192_cbc, "aes");
            provider.addalgorithm("alg.alias.algorithmparametergenerator." + nistobjectidentifiers.id_aes256_cbc, "aes");

            provider.addalgorithm("cipher.aes", prefix + "$ecb");
            provider.addalgorithm("alg.alias.cipher." + wrongaes128, "aes");
            provider.addalgorithm("alg.alias.cipher." + wrongaes192, "aes");
            provider.addalgorithm("alg.alias.cipher." + wrongaes256, "aes");
            provider.addalgorithm("cipher." + nistobjectidentifiers.id_aes128_ecb, prefix + "$ecb");
            provider.addalgorithm("cipher." + nistobjectidentifiers.id_aes192_ecb, prefix + "$ecb");
            provider.addalgorithm("cipher." + nistobjectidentifiers.id_aes256_ecb, prefix + "$ecb");
            provider.addalgorithm("cipher." + nistobjectidentifiers.id_aes128_cbc, prefix + "$cbc");
            provider.addalgorithm("cipher." + nistobjectidentifiers.id_aes192_cbc, prefix + "$cbc");
            provider.addalgorithm("cipher." + nistobjectidentifiers.id_aes256_cbc, prefix + "$cbc");
            provider.addalgorithm("cipher." + nistobjectidentifiers.id_aes128_ofb, prefix + "$ofb");
            provider.addalgorithm("cipher." + nistobjectidentifiers.id_aes192_ofb, prefix + "$ofb");
            provider.addalgorithm("cipher." + nistobjectidentifiers.id_aes256_ofb, prefix + "$ofb");
            provider.addalgorithm("cipher." + nistobjectidentifiers.id_aes128_cfb, prefix + "$cfb");
            provider.addalgorithm("cipher." + nistobjectidentifiers.id_aes192_cfb, prefix + "$cfb");
            provider.addalgorithm("cipher." + nistobjectidentifiers.id_aes256_cfb, prefix + "$cfb");
            provider.addalgorithm("cipher.aeswrap", prefix + "$wrap");
            provider.addalgorithm("alg.alias.cipher." + nistobjectidentifiers.id_aes128_wrap, "aeswrap");
            provider.addalgorithm("alg.alias.cipher." + nistobjectidentifiers.id_aes192_wrap, "aeswrap");
            provider.addalgorithm("alg.alias.cipher." + nistobjectidentifiers.id_aes256_wrap, "aeswrap");
            provider.addalgorithm("cipher.aesrfc3211wrap", prefix + "$rfc3211wrap");

            provider.addalgorithm("keygenerator.aes", prefix + "$keygen");
            provider.addalgorithm("keygenerator." + wrongaes128, prefix + "$keygen128");
            provider.addalgorithm("keygenerator." + wrongaes192, prefix + "$keygen192");
            provider.addalgorithm("keygenerator." + wrongaes256, prefix + "$keygen256");
            provider.addalgorithm("keygenerator." + nistobjectidentifiers.id_aes128_ecb, prefix + "$keygen128");
            provider.addalgorithm("keygenerator." + nistobjectidentifiers.id_aes128_cbc, prefix + "$keygen128");
            provider.addalgorithm("keygenerator." + nistobjectidentifiers.id_aes128_ofb, prefix + "$keygen128");
            provider.addalgorithm("keygenerator." + nistobjectidentifiers.id_aes128_cfb, prefix + "$keygen128");
            provider.addalgorithm("keygenerator." + nistobjectidentifiers.id_aes192_ecb, prefix + "$keygen192");
            provider.addalgorithm("keygenerator." + nistobjectidentifiers.id_aes192_cbc, prefix + "$keygen192");
            provider.addalgorithm("keygenerator." + nistobjectidentifiers.id_aes192_ofb, prefix + "$keygen192");
            provider.addalgorithm("keygenerator." + nistobjectidentifiers.id_aes192_cfb, prefix + "$keygen192");
            provider.addalgorithm("keygenerator." + nistobjectidentifiers.id_aes256_ecb, prefix + "$keygen256");
            provider.addalgorithm("keygenerator." + nistobjectidentifiers.id_aes256_cbc, prefix + "$keygen256");
            provider.addalgorithm("keygenerator." + nistobjectidentifiers.id_aes256_ofb, prefix + "$keygen256");
            provider.addalgorithm("keygenerator." + nistobjectidentifiers.id_aes256_cfb, prefix + "$keygen256");
            provider.addalgorithm("keygenerator.aeswrap", prefix + "$keygen");
            provider.addalgorithm("keygenerator." + nistobjectidentifiers.id_aes128_wrap, prefix + "$keygen128");
            provider.addalgorithm("keygenerator." + nistobjectidentifiers.id_aes192_wrap, prefix + "$keygen192");
            provider.addalgorithm("keygenerator." + nistobjectidentifiers.id_aes256_wrap, prefix + "$keygen256");

            provider.addalgorithm("mac.aescmac", prefix + "$aescmac");
            
            provider.addalgorithm("alg.alias.cipher." + bcobjectidentifiers.bc_pbe_sha1_pkcs12_aes128_cbc.getid(), "pbewithshaand128bitaes-cbc-bc");
            provider.addalgorithm("alg.alias.cipher." + bcobjectidentifiers.bc_pbe_sha1_pkcs12_aes192_cbc.getid(), "pbewithshaand192bitaes-cbc-bc");
            provider.addalgorithm("alg.alias.cipher." + bcobjectidentifiers.bc_pbe_sha1_pkcs12_aes256_cbc.getid(), "pbewithshaand256bitaes-cbc-bc");
            provider.addalgorithm("alg.alias.cipher." + bcobjectidentifiers.bc_pbe_sha256_pkcs12_aes128_cbc.getid(), "pbewithsha256and128bitaes-cbc-bc");
            provider.addalgorithm("alg.alias.cipher." + bcobjectidentifiers.bc_pbe_sha256_pkcs12_aes192_cbc.getid(), "pbewithsha256and192bitaes-cbc-bc");
            provider.addalgorithm("alg.alias.cipher." + bcobjectidentifiers.bc_pbe_sha256_pkcs12_aes256_cbc.getid(), "pbewithsha256and256bitaes-cbc-bc");
    
            provider.addalgorithm("cipher.pbewithshaand128bitaes-cbc-bc", prefix + "$pbewithaescbc");
            provider.addalgorithm("cipher.pbewithshaand192bitaes-cbc-bc", prefix + "$pbewithaescbc");
            provider.addalgorithm("cipher.pbewithshaand256bitaes-cbc-bc", prefix + "$pbewithaescbc");
            provider.addalgorithm("cipher.pbewithsha256and128bitaes-cbc-bc", prefix + "$pbewithaescbc");
            provider.addalgorithm("cipher.pbewithsha256and192bitaes-cbc-bc", prefix + "$pbewithaescbc");
            provider.addalgorithm("cipher.pbewithsha256and256bitaes-cbc-bc", prefix + "$pbewithaescbc");
            
            provider.addalgorithm("alg.alias.cipher.pbewithsha1and128bitaes-cbc-bc","pbewithshaand128bitaes-cbc-bc");
            provider.addalgorithm("alg.alias.cipher.pbewithsha1and192bitaes-cbc-bc","pbewithshaand192bitaes-cbc-bc");
            provider.addalgorithm("alg.alias.cipher.pbewithsha1and256bitaes-cbc-bc","pbewithshaand256bitaes-cbc-bc");
            provider.addalgorithm("alg.alias.cipher.pbewithsha-1and128bitaes-cbc-bc","pbewithshaand128bitaes-cbc-bc");
            provider.addalgorithm("alg.alias.cipher.pbewithsha-1and192bitaes-cbc-bc","pbewithshaand192bitaes-cbc-bc");
            provider.addalgorithm("alg.alias.cipher.pbewithsha-1and256bitaes-cbc-bc","pbewithshaand256bitaes-cbc-bc");
            provider.addalgorithm("alg.alias.cipher.pbewithsha-256and128bitaes-cbc-bc","pbewithsha256and128bitaes-cbc-bc");
            provider.addalgorithm("alg.alias.cipher.pbewithsha-256and192bitaes-cbc-bc","pbewithsha256and192bitaes-cbc-bc");
            provider.addalgorithm("alg.alias.cipher.pbewithsha-256and256bitaes-cbc-bc","pbewithsha256and256bitaes-cbc-bc");
            
            provider.addalgorithm("cipher.pbewithmd5and128bitaes-cbc-openssl", prefix + "$pbewithaescbc");
            provider.addalgorithm("cipher.pbewithmd5and192bitaes-cbc-openssl", prefix + "$pbewithaescbc");
            provider.addalgorithm("cipher.pbewithmd5and256bitaes-cbc-openssl", prefix + "$pbewithaescbc");
            
            provider.addalgorithm("secretkeyfactory.pbewithmd5and128bitaes-cbc-openssl", prefix + "$pbewithmd5and128bitaescbcopenssl");
            provider.addalgorithm("secretkeyfactory.pbewithmd5and192bitaes-cbc-openssl", prefix + "$pbewithmd5and192bitaescbcopenssl");
            provider.addalgorithm("secretkeyfactory.pbewithmd5and256bitaes-cbc-openssl", prefix + "$pbewithmd5and256bitaescbcopenssl");
            
            provider.addalgorithm("secretkeyfactory.pbewithshaand128bitaes-cbc-bc", prefix + "$pbewithshaand128bitaesbc");
            provider.addalgorithm("secretkeyfactory.pbewithshaand192bitaes-cbc-bc", prefix + "$pbewithshaand192bitaesbc");
            provider.addalgorithm("secretkeyfactory.pbewithshaand256bitaes-cbc-bc", prefix + "$pbewithshaand256bitaesbc");
            provider.addalgorithm("secretkeyfactory.pbewithsha256and128bitaes-cbc-bc", prefix + "$pbewithsha256and128bitaesbc");
            provider.addalgorithm("secretkeyfactory.pbewithsha256and192bitaes-cbc-bc", prefix + "$pbewithsha256and192bitaesbc");
            provider.addalgorithm("secretkeyfactory.pbewithsha256and256bitaes-cbc-bc", prefix + "$pbewithsha256and256bitaesbc");
            provider.addalgorithm("alg.alias.secretkeyfactory.pbewithsha1and128bitaes-cbc-bc","pbewithshaand128bitaes-cbc-bc");
            provider.addalgorithm("alg.alias.secretkeyfactory.pbewithsha1and192bitaes-cbc-bc","pbewithshaand192bitaes-cbc-bc");
            provider.addalgorithm("alg.alias.secretkeyfactory.pbewithsha1and256bitaes-cbc-bc","pbewithshaand256bitaes-cbc-bc");
            provider.addalgorithm("alg.alias.secretkeyfactory.pbewithsha-1and128bitaes-cbc-bc","pbewithshaand128bitaes-cbc-bc");
            provider.addalgorithm("alg.alias.secretkeyfactory.pbewithsha-1and192bitaes-cbc-bc","pbewithshaand192bitaes-cbc-bc");
            provider.addalgorithm("alg.alias.secretkeyfactory.pbewithsha-1and256bitaes-cbc-bc","pbewithshaand256bitaes-cbc-bc");
            provider.addalgorithm("alg.alias.secretkeyfactory.pbewithsha-256and128bitaes-cbc-bc","pbewithsha256and128bitaes-cbc-bc");
            provider.addalgorithm("alg.alias.secretkeyfactory.pbewithsha-256and192bitaes-cbc-bc","pbewithsha256and192bitaes-cbc-bc");
            provider.addalgorithm("alg.alias.secretkeyfactory.pbewithsha-256and256bitaes-cbc-bc","pbewithsha256and256bitaes-cbc-bc");
            provider.addalgorithm("alg.alias.secretkeyfactory." + bcobjectidentifiers.bc_pbe_sha1_pkcs12_aes128_cbc.getid(), "pbewithshaand128bitaes-cbc-bc");
            provider.addalgorithm("alg.alias.secretkeyfactory." + bcobjectidentifiers.bc_pbe_sha1_pkcs12_aes192_cbc.getid(), "pbewithshaand192bitaes-cbc-bc");
            provider.addalgorithm("alg.alias.secretkeyfactory." + bcobjectidentifiers.bc_pbe_sha1_pkcs12_aes256_cbc.getid(), "pbewithshaand256bitaes-cbc-bc");
            provider.addalgorithm("alg.alias.secretkeyfactory." + bcobjectidentifiers.bc_pbe_sha256_pkcs12_aes128_cbc.getid(), "pbewithsha256and128bitaes-cbc-bc");
            provider.addalgorithm("alg.alias.secretkeyfactory." + bcobjectidentifiers.bc_pbe_sha256_pkcs12_aes192_cbc.getid(), "pbewithsha256and192bitaes-cbc-bc");
            provider.addalgorithm("alg.alias.secretkeyfactory." + bcobjectidentifiers.bc_pbe_sha256_pkcs12_aes256_cbc.getid(), "pbewithsha256and256bitaes-cbc-bc");
            
            provider.addalgorithm("alg.alias.algorithmparameters.pbewithshaand128bitaes-cbc-bc", "pkcs12pbe");
            provider.addalgorithm("alg.alias.algorithmparameters.pbewithshaand192bitaes-cbc-bc", "pkcs12pbe");
            provider.addalgorithm("alg.alias.algorithmparameters.pbewithshaand256bitaes-cbc-bc", "pkcs12pbe");
            provider.addalgorithm("alg.alias.algorithmparameters.pbewithsha256and128bitaes-cbc-bc", "pkcs12pbe");
            provider.addalgorithm("alg.alias.algorithmparameters.pbewithsha256and192bitaes-cbc-bc", "pkcs12pbe");
            provider.addalgorithm("alg.alias.algorithmparameters.pbewithsha256and256bitaes-cbc-bc", "pkcs12pbe");
            provider.addalgorithm("alg.alias.algorithmparameters.pbewithsha1and128bitaes-cbc-bc","pkcs12pbe");
            provider.addalgorithm("alg.alias.algorithmparameters.pbewithsha1and192bitaes-cbc-bc","pkcs12pbe");
            provider.addalgorithm("alg.alias.algorithmparameters.pbewithsha1and256bitaes-cbc-bc","pkcs12pbe");
            provider.addalgorithm("alg.alias.algorithmparameters.pbewithsha-1and128bitaes-cbc-bc","pkcs12pbe");
            provider.addalgorithm("alg.alias.algorithmparameters.pbewithsha-1and192bitaes-cbc-bc","pkcs12pbe");
            provider.addalgorithm("alg.alias.algorithmparameters.pbewithsha-1and256bitaes-cbc-bc","pkcs12pbe");
            provider.addalgorithm("alg.alias.algorithmparameters.pbewithsha-256and128bitaes-cbc-bc","pkcs12pbe");
            provider.addalgorithm("alg.alias.algorithmparameters.pbewithsha-256and192bitaes-cbc-bc","pkcs12pbe");
            provider.addalgorithm("alg.alias.algorithmparameters.pbewithsha-256and256bitaes-cbc-bc","pkcs12pbe"); 
            
            provider.addalgorithm("alg.alias.algorithmparameters." + bcobjectidentifiers.bc_pbe_sha1_pkcs12_aes128_cbc.getid(), "pkcs12pbe");
            provider.addalgorithm("alg.alias.algorithmparameters." + bcobjectidentifiers.bc_pbe_sha1_pkcs12_aes192_cbc.getid(), "pkcs12pbe");
            provider.addalgorithm("alg.alias.algorithmparameters." + bcobjectidentifiers.bc_pbe_sha1_pkcs12_aes256_cbc.getid(), "pkcs12pbe");
            provider.addalgorithm("alg.alias.algorithmparameters." + bcobjectidentifiers.bc_pbe_sha256_pkcs12_aes128_cbc.getid(), "pkcs12pbe");
            provider.addalgorithm("alg.alias.algorithmparameters." + bcobjectidentifiers.bc_pbe_sha256_pkcs12_aes192_cbc.getid(), "pkcs12pbe");
            provider.addalgorithm("alg.alias.algorithmparameters." + bcobjectidentifiers.bc_pbe_sha256_pkcs12_aes256_cbc.getid(), "pkcs12pbe");

            addgmacalgorithm(provider, "aes", prefix + "$aesgmac", prefix + "$keygen128");
        }
    }
}
