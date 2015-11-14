package org.ripple.bouncycastle.jcajce.provider.symmetric;

import java.security.algorithmparameters;
import java.security.invalidalgorithmparameterexception;
import java.security.securerandom;
import java.security.spec.algorithmparameterspec;
import java.security.spec.invalidkeyspecexception;
import java.security.spec.keyspec;

import javax.crypto.secretkey;
import javax.crypto.spec.deskeyspec;
import javax.crypto.spec.ivparameterspec;
import javax.crypto.spec.pbekeyspec;
import javax.crypto.spec.secretkeyspec;

import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.oiw.oiwobjectidentifiers;
import org.ripple.bouncycastle.asn1.pkcs.pkcsobjectidentifiers;
import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.keygenerationparameters;
import org.ripple.bouncycastle.crypto.engines.desengine;
import org.ripple.bouncycastle.crypto.engines.rfc3211wrapengine;
import org.ripple.bouncycastle.crypto.generators.deskeygenerator;
import org.ripple.bouncycastle.crypto.macs.cbcblockciphermac;
import org.ripple.bouncycastle.crypto.macs.cfbblockciphermac;
import org.ripple.bouncycastle.crypto.macs.cmac;
import org.ripple.bouncycastle.crypto.macs.iso9797alg3mac;
import org.ripple.bouncycastle.crypto.modes.cbcblockcipher;
import org.ripple.bouncycastle.crypto.paddings.iso7816d4padding;
import org.ripple.bouncycastle.crypto.params.desparameters;
import org.ripple.bouncycastle.crypto.params.keyparameter;
import org.ripple.bouncycastle.crypto.params.parameterswithiv;
import org.ripple.bouncycastle.jcajce.provider.config.configurableprovider;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.bcpbekey;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.basealgorithmparametergenerator;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.baseblockcipher;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.basekeygenerator;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.basemac;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.basesecretkeyfactory;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.basewrapcipher;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.pbe;
import org.ripple.bouncycastle.jcajce.provider.util.algorithmprovider;
import org.ripple.bouncycastle.jce.provider.bouncycastleprovider;

public final class des
{
    private des()
    {
    }

    static public class ecb
        extends baseblockcipher
    {
        public ecb()
        {
            super(new desengine());
        }
    }

    static public class cbc
        extends baseblockcipher
    {
        public cbc()
        {
            super(new cbcblockcipher(new desengine()), 64);
        }
    }

    /**
     * des   cfb8
     */
    public static class descfb8
        extends basemac
    {
        public descfb8()
        {
            super(new cfbblockciphermac(new desengine()));
        }
    }

    /**
     * des64
     */
    public static class des64
        extends basemac
    {
        public des64()
        {
            super(new cbcblockciphermac(new desengine(), 64));
        }
    }

    /**
     * des64with7816-4padding
     */
    public static class des64with7816d4
        extends basemac
    {
        public des64with7816d4()
        {
            super(new cbcblockciphermac(new desengine(), 64, new iso7816d4padding()));
        }
    }
    
    public static class cbcmac
        extends basemac
    {
        public cbcmac()
        {
            super(new cbcblockciphermac(new desengine()));
        }
    }

    static public class cmac
        extends basemac
    {
        public cmac()
        {
            super(new cmac(new desengine()));
        }
    }

    /**
     * des9797alg3with7816-4padding
     */
    public static class des9797alg3with7816d4
        extends basemac
    {
        public des9797alg3with7816d4()
        {
            super(new iso9797alg3mac(new desengine(), new iso7816d4padding()));
        }
    }

    /**
     * des9797alg3
     */
    public static class des9797alg3
        extends basemac
    {
        public des9797alg3()
        {
            super(new iso9797alg3mac(new desengine()));
        }
    }

    public static class rfc3211
        extends basewrapcipher
    {
        public rfc3211()
        {
            super(new rfc3211wrapengine(new desengine()), 8);
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

  /**
     * des - the default for this is to generate a key in
     * a-b-a format that's 24 bytes long but has 16 bytes of
     * key material (the first 8 bytes is repeated as the last
     * 8 bytes). if you give it a size, you'll get just what you
     * asked for.
     */
    public static class keygenerator
        extends basekeygenerator
    {
        public keygenerator()
        {
            super("des", 64, new deskeygenerator());
        }

        protected void engineinit(
            int             keysize,
            securerandom random)
        {
            super.engineinit(keysize, random);
        }

        protected secretkey enginegeneratekey()
        {
            if (uninitialised)
            {
                engine.init(new keygenerationparameters(new securerandom(), defaultkeysize));
                uninitialised = false;
            }

            return new secretkeyspec(engine.generatekey(), algname);
        }
    }

    static public class keyfactory
        extends basesecretkeyfactory
    {
        public keyfactory()
        {
            super("des", null);
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
            else if (deskeyspec.class.isassignablefrom(keyspec))
            {
                byte[]  bytes = key.getencoded();

                try
                {
                    return new deskeyspec(bytes);
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
            if (keyspec instanceof deskeyspec)
            {
                deskeyspec deskeyspec = (deskeyspec)keyspec;
                return new secretkeyspec(deskeyspec.getkey(), "des");
            }

            return super.enginegeneratesecret(keyspec);
        }
    }

    static public class despbekeyfactory
        extends basesecretkeyfactory
    {
        private boolean forcipher;
        private int     scheme;
        private int     digest;
        private int     keysize;
        private int     ivsize;

        public despbekeyfactory(
            string              algorithm,
            asn1objectidentifier oid,
            boolean             forcipher,
            int                 scheme,
            int                 digest,
            int                 keysize,
            int                 ivsize)
        {
            super(algorithm, oid);

            this.forcipher = forcipher;
            this.scheme = scheme;
            this.digest = digest;
            this.keysize = keysize;
            this.ivsize = ivsize;
        }

        protected secretkey enginegeneratesecret(
            keyspec keyspec)
        throws invalidkeyspecexception
        {
            if (keyspec instanceof pbekeyspec)
            {
                pbekeyspec pbespec = (pbekeyspec)keyspec;
                cipherparameters param;

                if (pbespec.getsalt() == null)
                {
                    return new bcpbekey(this.algname, this.algoid, scheme, digest, keysize, ivsize, pbespec, null);
                }

                if (forcipher)
                {
                    param = pbe.util.makepbeparameters(pbespec, scheme, digest, keysize, ivsize);
                }
                else
                {
                    param = pbe.util.makepbemacparameters(pbespec, scheme, digest, keysize);
                }

                keyparameter kparam;
                if (param instanceof parameterswithiv)
                {
                    kparam = (keyparameter)((parameterswithiv)param).getparameters();
                }
                else
                {
                    kparam = (keyparameter)param;
                }

                desparameters.setoddparity(kparam.getkey());

                return new bcpbekey(this.algname, this.algoid, scheme, digest, keysize, ivsize, pbespec, param);
            }

            throw new invalidkeyspecexception("invalid keyspec");
        }
    }

    /**
     * pbewithmd2anddes
     */
    static public class pbewithmd2keyfactory
        extends despbekeyfactory
    {
        public pbewithmd2keyfactory()
        {
            super("pbewithmd2anddes", pkcsobjectidentifiers.pbewithmd2anddes_cbc, true, pkcs5s1, md2, 64, 64);
        }
    }

    /**
     * pbewithmd5anddes
     */
    static public class pbewithmd5keyfactory
        extends despbekeyfactory
    {
        public pbewithmd5keyfactory()
        {
            super("pbewithmd5anddes", pkcsobjectidentifiers.pbewithmd5anddes_cbc, true, pkcs5s1, md5, 64, 64);
        }
    }

    /**
     * pbewithsha1anddes
     */
    static public class pbewithsha1keyfactory
        extends despbekeyfactory
    {
        public pbewithsha1keyfactory()
        {
            super("pbewithsha1anddes", pkcsobjectidentifiers.pbewithsha1anddes_cbc, true, pkcs5s1, sha1, 64, 64);
        }
    }

    /**
     * pbewithmd2anddes
     */
    static public class pbewithmd2
        extends baseblockcipher
    {
        public pbewithmd2()
        {
            super(new cbcblockcipher(new desengine()));
        }
    }

    /**
     * pbewithmd5anddes
     */
    static public class pbewithmd5
        extends baseblockcipher
    {
        public pbewithmd5()
        {
            super(new cbcblockcipher(new desengine()));
        }
    }

    /**
     * pbewithsha1anddes
     */
    static public class pbewithsha1
        extends baseblockcipher
    {
        public pbewithsha1()
        {
            super(new cbcblockcipher(new desengine()));
        }
    }
    
    public static class mappings
        extends algorithmprovider
    {
        private static final string prefix = des.class.getname();
        private static final string package = "org.bouncycastle.jcajce.provider.symmetric"; // jdk 1.2

        public mappings()
        {
        }

        public void configure(configurableprovider provider)
        {

            provider.addalgorithm("cipher.des", prefix + "$ecb");
            provider.addalgorithm("cipher." + oiwobjectidentifiers.descbc, prefix + "$cbc");

            addalias(provider, oiwobjectidentifiers.descbc, "des");

            provider.addalgorithm("cipher.desrfc3211wrap", prefix + "$rfc3211");

            provider.addalgorithm("keygenerator.des", prefix + "$keygenerator");

            provider.addalgorithm("secretkeyfactory.des", prefix + "$keyfactory");

            provider.addalgorithm("mac.descmac", prefix + "$cmac");
            provider.addalgorithm("mac.desmac", prefix + "$cbcmac");
            provider.addalgorithm("alg.alias.mac.des", "desmac");

            provider.addalgorithm("mac.desmac/cfb8", prefix + "$descfb8");
            provider.addalgorithm("alg.alias.mac.des/cfb8", "desmac/cfb8");

            provider.addalgorithm("mac.desmac64", prefix + "$des64");
            provider.addalgorithm("alg.alias.mac.des64", "desmac64");

            provider.addalgorithm("mac.desmac64withiso7816-4padding", prefix + "$des64with7816d4");
            provider.addalgorithm("alg.alias.mac.des64withiso7816-4padding", "desmac64withiso7816-4padding");
            provider.addalgorithm("alg.alias.mac.desiso9797alg1macwithiso7816-4padding", "desmac64withiso7816-4padding");
            provider.addalgorithm("alg.alias.mac.desiso9797alg1withiso7816-4padding", "desmac64withiso7816-4padding");

            provider.addalgorithm("mac.deswithiso9797", prefix + "$des9797alg3");
            provider.addalgorithm("alg.alias.mac.desiso9797mac", "deswithiso9797");

            provider.addalgorithm("mac.iso9797alg3mac", prefix + "$des9797alg3");
            provider.addalgorithm("alg.alias.mac.iso9797alg3", "iso9797alg3mac");
            provider.addalgorithm("mac.iso9797alg3withiso7816-4padding", prefix + "$des9797alg3with7816d4");
            provider.addalgorithm("alg.alias.mac.iso9797alg3macwithiso7816-4padding", "iso9797alg3withiso7816-4padding");

            provider.addalgorithm("algorithmparameters.des", package + ".util.ivalgorithmparameters");
            provider.addalgorithm("alg.alias.algorithmparameters." + oiwobjectidentifiers.descbc, "des");

            provider.addalgorithm("algorithmparametergenerator.des",  prefix + "$algparamgen");
            provider.addalgorithm("alg.alias.algorithmparametergenerator." + oiwobjectidentifiers.descbc, "des");

            provider.addalgorithm("cipher.pbewithmd2anddes", prefix + "$pbewithmd2");
            provider.addalgorithm("cipher.pbewithmd5anddes", prefix + "$pbewithmd5");
            provider.addalgorithm("cipher.pbewithsha1anddes", prefix + "$pbewithsha1");
            
            provider.addalgorithm("alg.alias.cipher." + pkcsobjectidentifiers.pbewithmd2anddes_cbc, "pbewithmd2anddes");
            provider.addalgorithm("alg.alias.cipher." + pkcsobjectidentifiers.pbewithmd5anddes_cbc, "pbewithmd5anddes");
            provider.addalgorithm("alg.alias.cipher." + pkcsobjectidentifiers.pbewithsha1anddes_cbc, "pbewithsha1anddes");
            
            provider.addalgorithm("secretkeyfactory.pbewithmd2anddes", prefix + "$pbewithmd2keyfactory");
            provider.addalgorithm("secretkeyfactory.pbewithmd5anddes", prefix + "$pbewithmd5keyfactory");
            provider.addalgorithm("secretkeyfactory.pbewithsha1anddes", prefix + "$pbewithsha1keyfactory");

            provider.addalgorithm("alg.alias.secretkeyfactory.pbewithmd2anddes-cbc", "pbewithmd2anddes");
            provider.addalgorithm("alg.alias.secretkeyfactory.pbewithmd5anddes-cbc", "pbewithmd5anddes");
            provider.addalgorithm("alg.alias.secretkeyfactory.pbewithsha1anddes-cbc", "pbewithsha1anddes");
            provider.addalgorithm("alg.alias.secretkeyfactory." + pkcsobjectidentifiers.pbewithmd2anddes_cbc, "pbewithmd2anddes");
            provider.addalgorithm("alg.alias.secretkeyfactory." + pkcsobjectidentifiers.pbewithmd5anddes_cbc, "pbewithmd5anddes");
            provider.addalgorithm("alg.alias.secretkeyfactory." + pkcsobjectidentifiers.pbewithsha1anddes_cbc, "pbewithsha1anddes");
        }

        private void addalias(configurableprovider provider, asn1objectidentifier oid, string name)
        {
            provider.addalgorithm("alg.alias.keygenerator." + oid.getid(), name);
            provider.addalgorithm("alg.alias.keyfactory." + oid.getid(), name);
        }
    }
}
