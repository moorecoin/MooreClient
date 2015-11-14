package org.ripple.bouncycastle.jcajce.provider.symmetric;

import java.security.algorithmparameters;
import java.security.invalidalgorithmparameterexception;
import java.security.securerandom;
import java.security.spec.algorithmparameterspec;
import java.security.spec.invalidkeyspecexception;
import java.security.spec.keyspec;

import javax.crypto.secretkey;
import javax.crypto.spec.desedekeyspec;
import javax.crypto.spec.ivparameterspec;
import javax.crypto.spec.secretkeyspec;

import org.ripple.bouncycastle.asn1.pkcs.pkcsobjectidentifiers;
import org.ripple.bouncycastle.crypto.keygenerationparameters;
import org.ripple.bouncycastle.crypto.engines.desedeengine;
import org.ripple.bouncycastle.crypto.engines.desedewrapengine;
import org.ripple.bouncycastle.crypto.engines.rfc3211wrapengine;
import org.ripple.bouncycastle.crypto.generators.desedekeygenerator;
import org.ripple.bouncycastle.crypto.macs.cbcblockciphermac;
import org.ripple.bouncycastle.crypto.macs.cfbblockciphermac;
import org.ripple.bouncycastle.crypto.macs.cmac;
import org.ripple.bouncycastle.crypto.modes.cbcblockcipher;
import org.ripple.bouncycastle.crypto.paddings.iso7816d4padding;
import org.ripple.bouncycastle.jcajce.provider.config.configurableprovider;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.basealgorithmparametergenerator;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.baseblockcipher;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.basekeygenerator;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.basemac;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.basesecretkeyfactory;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.basewrapcipher;
import org.ripple.bouncycastle.jcajce.provider.util.algorithmprovider;
import org.ripple.bouncycastle.jce.provider.bouncycastleprovider;

public final class desede
{
    private desede()
    {
    }

    static public class ecb
        extends baseblockcipher
    {
        public ecb()
        {
            super(new desedeengine());
        }
    }

    static public class cbc
        extends baseblockcipher
    {
        public cbc()
        {
            super(new cbcblockcipher(new desedeengine()), 64);
        }
    }

    /**
     * desede   cfb8
     */
    public static class desedecfb8
        extends basemac
    {
        public desedecfb8()
        {
            super(new cfbblockciphermac(new desedeengine()));
        }
    }

    /**
     * desede64
     */
    public static class desede64
        extends basemac
    {
        public desede64()
        {
            super(new cbcblockciphermac(new desedeengine(), 64));
        }
    }

    /**
     * desede64with7816-4padding
     */
    public static class desede64with7816d4
        extends basemac
    {
        public desede64with7816d4()
        {
            super(new cbcblockciphermac(new desedeengine(), 64, new iso7816d4padding()));
        }
    }
    
    public static class cbcmac
        extends basemac
    {
        public cbcmac()
        {
            super(new cbcblockciphermac(new desedeengine()));
        }
    }

    static public class cmac
        extends basemac
    {
        public cmac()
        {
            super(new cmac(new desedeengine()));
        }
    }

    public static class wrap
        extends basewrapcipher
    {
        public wrap()
        {
            super(new desedewrapengine());
        }
    }

    public static class rfc3211
        extends basewrapcipher
    {
        public rfc3211()
        {
            super(new rfc3211wrapengine(new desedeengine()), 8);
        }
    }

  /**
     * desede - the default for this is to generate a key in
     * a-b-a format that's 24 bytes long but has 16 bytes of
     * key material (the first 8 bytes is repeated as the last
     * 8 bytes). if you give it a size, you'll get just what you
     * asked for.
     */
    public static class keygenerator
        extends basekeygenerator
    {
        private boolean     keysizeset = false;

        public keygenerator()
        {
            super("desede", 192, new desedekeygenerator());
        }

        protected void engineinit(
            int             keysize,
            securerandom random)
        {
            super.engineinit(keysize, random);
            keysizeset = true;
        }

        protected secretkey enginegeneratekey()
        {
            if (uninitialised)
            {
                engine.init(new keygenerationparameters(new securerandom(), defaultkeysize));
                uninitialised = false;
            }

            //
            // if no key size has been defined generate a 24 byte key in
            // the a-b-a format
            //
            if (!keysizeset)
            {
                byte[]     k = engine.generatekey();

                system.arraycopy(k, 0, k, 16, 8);

                return new secretkeyspec(k, algname);
            }
            else
            {
                return new secretkeyspec(engine.generatekey(), algname);
            }
        }
    }

    /**
     * generate a desede key in the a-b-c format.
     */
    public static class keygenerator3
        extends basekeygenerator
    {
        public keygenerator3()
        {
            super("desede3", 192, new desedekeygenerator());
        }
    }

    /**
     * pbewithshaand3-keytripledes-cbc
     */
    static public class pbewithshaanddes3key
        extends baseblockcipher
    {
        public pbewithshaanddes3key()
        {
            super(new cbcblockcipher(new desedeengine()));
        }
    }

    /**
     * pbewithshaand2-keytripledes-cbc
     */
    static public class pbewithshaanddes2key
        extends baseblockcipher
    {
        public pbewithshaanddes2key()
        {
            super(new cbcblockcipher(new desedeengine()));
        }
    }

    /**
     * pbewithshaand3-keytripledes-cbc
     */
    static public class pbewithshaanddes3keyfactory
        extends des.despbekeyfactory
    {
        public pbewithshaanddes3keyfactory()
        {
            super("pbewithshaanddes3key-cbc", pkcsobjectidentifiers.pbewithshaand3_keytripledes_cbc, true, pkcs12, sha1, 192, 64);
        }
    }

    /**
     * pbewithshaand2-keytripledes-cbc
     */
    static public class pbewithshaanddes2keyfactory
        extends des.despbekeyfactory
    {
        public pbewithshaanddes2keyfactory()
        {
            super("pbewithshaanddes2key-cbc", pkcsobjectidentifiers.pbewithshaand2_keytripledes_cbc, true, pkcs12, sha1, 128, 64);
        }
    }

    public static class algparamgen
        extends basealgorithmparametergenerator
    {
        protected void engineinit(
            algorithmparameterspec genparamspec,
            securerandom            random)
            throws invalidalgorithmparameterexception
        {
            throw new invalidalgorithmparameterexception("no supported algorithmparameterspec for des parameter generation.");
        }

        protected algorithmparameters enginegenerateparameters()
        {
            byte[]  iv = new byte[8];

            if (random == null)
            {
                random = new securerandom();
            }

            random.nextbytes(iv);

            algorithmparameters params;

            try
            {
                params = algorithmparameters.getinstance("des", bouncycastleprovider.provider_name);
                params.init(new ivparameterspec(iv));
            }
            catch (exception e)
            {
                throw new runtimeexception(e.getmessage());
            }

            return params;
        }
    }

    static public class keyfactory
        extends basesecretkeyfactory
    {
        public keyfactory()
        {
            super("desede", null);
        }

        protected keyspec enginegetkeyspec(
            secretkey key,
            class keyspec)
        throws invalidkeyspecexception
        {
            if (keyspec == null)
            {
                throw new invalidkeyspecexception("keyspec parameter is null");
            }
            if (key == null)
            {
                throw new invalidkeyspecexception("key parameter is null");
            }

            if (secretkeyspec.class.isassignablefrom(keyspec))
            {
                return new secretkeyspec(key.getencoded(), algname);
            }
            else if (desedekeyspec.class.isassignablefrom(keyspec))
            {
                byte[]  bytes = key.getencoded();

                try
                {
                    if (bytes.length == 16)
                    {
                        byte[]  longkey = new byte[24];

                        system.arraycopy(bytes, 0, longkey, 0, 16);
                        system.arraycopy(bytes, 0, longkey, 16, 8);

                        return new desedekeyspec(longkey);
                    }
                    else
                    {
                        return new desedekeyspec(bytes);
                    }
                }
                catch (exception e)
                {
                    throw new invalidkeyspecexception(e.tostring());
                }
            }

            throw new invalidkeyspecexception("invalid keyspec");
        }

        protected secretkey enginegeneratesecret(
            keyspec keyspec)
        throws invalidkeyspecexception
        {
            if (keyspec instanceof desedekeyspec)
            {
                desedekeyspec deskeyspec = (desedekeyspec)keyspec;
                return new secretkeyspec(deskeyspec.getkey(), "desede");
            }

            return super.enginegeneratesecret(keyspec);
        }
    }

    public static class mappings
        extends algorithmprovider
    {
        private static final string prefix = desede.class.getname();
        private static final string package = "org.bouncycastle.jcajce.provider.symmetric"; // jdk 1.2
                
        public mappings()
        {
        }

        public void configure(configurableprovider provider)
        {
            provider.addalgorithm("cipher.desede", prefix + "$ecb");
            provider.addalgorithm("cipher." + pkcsobjectidentifiers.des_ede3_cbc, prefix + "$cbc");
            provider.addalgorithm("cipher.desedewrap", prefix + "$wrap");
            provider.addalgorithm("cipher." + pkcsobjectidentifiers.id_alg_cms3deswrap, prefix + "$wrap");
            provider.addalgorithm("cipher.desederfc3211wrap", prefix + "$rfc3211");

            provider.addalgorithm("alg.alias.cipher.tdea", "desede");
            provider.addalgorithm("alg.alias.cipher.tdeawrap", "desedewrap");
            provider.addalgorithm("alg.alias.keygenerator.tdea", "desede");
            provider.addalgorithm("alg.alias.algorithmparameters.tdea", "desede");
            provider.addalgorithm("alg.alias.algorithmparametergenerator.tdea", "desede");
            provider.addalgorithm("alg.alias.secretkeyfactory.tdea", "desede");

            if (provider.hasalgorithm("messagedigest", "sha-1"))
            {
                provider.addalgorithm("cipher.pbewithshaand3-keytripledes-cbc", prefix + "$pbewithshaanddes3key");
                provider.addalgorithm("cipher.brokenpbewithshaand3-keytripledes-cbc", prefix + "$brokepbewithshaanddes3key");
                provider.addalgorithm("cipher.oldpbewithshaand3-keytripledes-cbc", prefix + "$oldpbewithshaanddes3key");
                provider.addalgorithm("cipher.pbewithshaand2-keytripledes-cbc", prefix + "$pbewithshaanddes2key");
                provider.addalgorithm("cipher.brokenpbewithshaand2-keytripledes-cbc", prefix + "$brokepbewithshaanddes2key");
                provider.addalgorithm("alg.alias.cipher." + pkcsobjectidentifiers.pbewithshaand3_keytripledes_cbc, "pbewithshaand3-keytripledes-cbc");
                provider.addalgorithm("alg.alias.cipher." + pkcsobjectidentifiers.pbewithshaand2_keytripledes_cbc, "pbewithshaand2-keytripledes-cbc");
                provider.addalgorithm("alg.alias.cipher.pbewithsha1anddesede", "pbewithshaand3-keytripledes-cbc");
                provider.addalgorithm("alg.alias.cipher.pbewithsha1and3-keytripledes-cbc", "pbewithshaand3-keytripledes-cbc");
                provider.addalgorithm("alg.alias.cipher.pbewithsha1and2-keytripledes-cbc", "pbewithshaand2-keytripledes-cbc");
            }

            provider.addalgorithm("keygenerator.desede", prefix + "$keygenerator");
            provider.addalgorithm("keygenerator." + pkcsobjectidentifiers.des_ede3_cbc, prefix + "$keygenerator3");
            provider.addalgorithm("keygenerator.desedewrap", prefix + "$keygenerator");

            provider.addalgorithm("secretkeyfactory.desede", prefix + "$keyfactory");

            provider.addalgorithm("mac.desedecmac", prefix + "$cmac");
            provider.addalgorithm("mac.desedemac", prefix + "$cbcmac");
            provider.addalgorithm("alg.alias.mac.desede", "desedemac");

            provider.addalgorithm("mac.desedemac/cfb8", prefix + "$desedecfb8");
            provider.addalgorithm("alg.alias.mac.desede/cfb8", "desedemac/cfb8");

            provider.addalgorithm("mac.desedemac64", prefix + "$desede64");
            provider.addalgorithm("alg.alias.mac.desede64", "desedemac64");

            provider.addalgorithm("mac.desedemac64withiso7816-4padding", prefix + "$desede64with7816d4");
            provider.addalgorithm("alg.alias.mac.desede64withiso7816-4padding", "desedemac64withiso7816-4padding");
            provider.addalgorithm("alg.alias.mac.desedeiso9797alg1macwithiso7816-4padding", "desedemac64withiso7816-4padding");
            provider.addalgorithm("alg.alias.mac.desedeiso9797alg1withiso7816-4padding", "desedemac64withiso7816-4padding");

            provider.addalgorithm("algorithmparameters.desede", package + ".util.ivalgorithmparameters");
            provider.addalgorithm("alg.alias.algorithmparameters." + pkcsobjectidentifiers.des_ede3_cbc, "desede");

            provider.addalgorithm("algorithmparametergenerator.desede",  prefix + "$algparamgen");
            provider.addalgorithm("alg.alias.algorithmparametergenerator." + pkcsobjectidentifiers.des_ede3_cbc, "desede");

            provider.addalgorithm("secretkeyfactory.pbewithshaand3-keytripledes-cbc", prefix + "$pbewithshaanddes3keyfactory");
            provider.addalgorithm("secretkeyfactory.pbewithshaand2-keytripledes-cbc", prefix + "$pbewithshaanddes2keyfactory");

            provider.addalgorithm("alg.alias.algorithmparameters.pbewithshaand3-keytripledes", "pkcs12pbe");
            provider.addalgorithm("alg.alias.algorithmparameters.pbewithshaand2-keytripledes", "pkcs12pbe");
            provider.addalgorithm("alg.alias.algorithmparameters.pbewithshaand3-keytripledes-cbc", "pkcs12pbe");
            provider.addalgorithm("alg.alias.algorithmparameters.pbewithshaand2-keytripledes-cbc", "pkcs12pbe");
            provider.addalgorithm("alg.alias.algorithmparameters.pbewithshaanddes3key-cbc", "pkcs12pbe");
            provider.addalgorithm("alg.alias.algorithmparameters.pbewithshaanddes2key-cbc", "pkcs12pbe");

            provider.addalgorithm("alg.alias.secretkeyfactory.1.2.840.113549.1.12.1.3", "pbewithshaand3-keytripledes-cbc");
            provider.addalgorithm("alg.alias.secretkeyfactory.1.2.840.113549.1.12.1.4", "pbewithshaand2-keytripledes-cbc");
            provider.addalgorithm("alg.alias.secretkeyfactory.pbewithshaand3keytripledes", "pbewithshaand3-keytripledes-cbc");
            provider.addalgorithm("alg.alias.algorithmparameters.1.2.840.113549.1.12.1.3", "pkcs12pbe");
            provider.addalgorithm("alg.alias.algorithmparameters.1.2.840.113549.1.12.1.4", "pkcs12pbe");
            provider.addalgorithm("alg.alias.cipher.pbewithshaand3keytripledes",  "pbewithshaand3-keytripledes-cbc");
        }
    }
}
