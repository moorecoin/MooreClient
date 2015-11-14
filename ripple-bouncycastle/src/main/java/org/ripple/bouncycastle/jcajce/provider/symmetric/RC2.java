package org.ripple.bouncycastle.jcajce.provider.symmetric;

import java.io.ioexception;
import java.security.algorithmparameters;
import java.security.invalidalgorithmparameterexception;
import java.security.securerandom;
import java.security.spec.algorithmparameterspec;
import java.security.spec.invalidparameterspecexception;

import javax.crypto.spec.ivparameterspec;
import javax.crypto.spec.rc2parameterspec;

import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.pkcs.pkcsobjectidentifiers;
import org.ripple.bouncycastle.asn1.pkcs.rc2cbcparameter;
import org.ripple.bouncycastle.crypto.cipherkeygenerator;
import org.ripple.bouncycastle.crypto.engines.rc2engine;
import org.ripple.bouncycastle.crypto.engines.rc2wrapengine;
import org.ripple.bouncycastle.crypto.macs.cbcblockciphermac;
import org.ripple.bouncycastle.crypto.macs.cfbblockciphermac;
import org.ripple.bouncycastle.crypto.modes.cbcblockcipher;
import org.ripple.bouncycastle.jcajce.provider.config.configurableprovider;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.basealgorithmparametergenerator;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.basealgorithmparameters;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.baseblockcipher;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.basekeygenerator;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.basemac;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.basewrapcipher;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.pbesecretkeyfactory;
import org.ripple.bouncycastle.jcajce.provider.util.algorithmprovider;
import org.ripple.bouncycastle.jce.provider.bouncycastleprovider;
import org.ripple.bouncycastle.util.arrays;

public final class rc2
{
    private rc2()
    {
    }

    /**
     * rc2
     */
    static public class ecb
        extends baseblockcipher
    {
        public ecb()
        {
            super(new rc2engine());
        }
    }

    /**
     * rc2cbc
     */
    static public class cbc
        extends baseblockcipher
    {
        public cbc()
        {
            super(new cbcblockcipher(new rc2engine()), 64);
        }
    }

    public static class wrap
        extends basewrapcipher
    {
        public wrap()
        {
            super(new rc2wrapengine());
        }
    }

    /**
     * rc2
     */
    public static class cbcmac
        extends basemac
    {
        public cbcmac()
        {
            super(new cbcblockciphermac(new rc2engine()));
        }
    }

    public static class cfb8mac
        extends basemac
    {
        public cfb8mac()
        {
            super(new cfbblockciphermac(new rc2engine()));
        }
    }

    /**
     * pbewithsha1andrc2
     */
    static public class pbewithsha1keyfactory
        extends pbesecretkeyfactory
    {
        public pbewithsha1keyfactory()
        {
            super("pbewithsha1andrc2", pkcsobjectidentifiers.pbewithsha1andrc2_cbc, true, pkcs5s1, sha1, 64, 64);
        }
    }

    /**
     * pbewithshaand128bitrc2-cbc
     */
    static public class pbewithshaand128bitkeyfactory
        extends pbesecretkeyfactory
    {
        public pbewithshaand128bitkeyfactory()
        {
            super("pbewithshaand128bitrc2-cbc", pkcsobjectidentifiers.pbewithshaand128bitrc2_cbc, true, pkcs12, sha1, 128, 64);
        }
    }

    /**
     * pbewithshaand40bitrc2-cbc
     */
    static public class pbewithshaand40bitkeyfactory
        extends pbesecretkeyfactory
    {
        public pbewithshaand40bitkeyfactory()
        {
            super("pbewithshaand40bitrc2-cbc", pkcsobjectidentifiers.pbewithshaand40bitrc2_cbc, true, pkcs12, sha1, 40, 64);
        }
    }

    /**
     * pbewithmd5andrc2
     */
    static public class pbewithmd5andrc2
        extends baseblockcipher
    {
        public pbewithmd5andrc2()
        {
            super(new cbcblockcipher(new rc2engine()));
        }
    }
    
    /**
     * pbewithsha1andrc2
     */
    static public class pbewithsha1andrc2
        extends baseblockcipher
    {
        public pbewithsha1andrc2()
        {
            super(new cbcblockcipher(new rc2engine()));
        }
    }

    /**
     * pbewithshaand128bitrc2-cbc
     */
    static public class pbewithshaand128bitrc2
        extends baseblockcipher
    {
        public pbewithshaand128bitrc2()
        {
            super(new cbcblockcipher(new rc2engine()));
        }
    }

    /**
     * pbewithshaand40bitrc2-cbc
     */
    static public class pbewithshaand40bitrc2
        extends baseblockcipher
    {
        public pbewithshaand40bitrc2()
        {
            super(new cbcblockcipher(new rc2engine()));
        }
    }

    /**
     * pbewithmd2andrc2
     */
    static public class pbewithmd2keyfactory
        extends pbesecretkeyfactory
    {
        public pbewithmd2keyfactory()
        {
            super("pbewithmd2andrc2", pkcsobjectidentifiers.pbewithmd2andrc2_cbc, true, pkcs5s1, md2, 64, 64);
        }
    }

   /**
    * pbewithmd5andrc2
    */
   static public class pbewithmd5keyfactory
       extends pbesecretkeyfactory
   {
       public pbewithmd5keyfactory()
       {
           super("pbewithmd5andrc2", pkcsobjectidentifiers.pbewithmd5andrc2_cbc, true, pkcs5s1, md5, 64, 64);
       }
   }

    public static class algparamgen
        extends basealgorithmparametergenerator
    {
        rc2parameterspec spec = null;

        protected void engineinit(
            algorithmparameterspec genparamspec,
            securerandom random)
            throws invalidalgorithmparameterexception
        {
            if (genparamspec instanceof rc2parameterspec)
            {
                spec = (rc2parameterspec)genparamspec;
                return;
            }

            throw new invalidalgorithmparameterexception("no supported algorithmparameterspec for rc2 parameter generation.");
        }

        protected algorithmparameters enginegenerateparameters()
        {
            algorithmparameters params;

            if (spec == null)
            {
                byte[] iv = new byte[8];

                if (random == null)
                {
                    random = new securerandom();
                }

                random.nextbytes(iv);

                try
                {
                    params = algorithmparameters.getinstance("rc2", bouncycastleprovider.provider_name);
                    params.init(new ivparameterspec(iv));
                }
                catch (exception e)
                {
                    throw new runtimeexception(e.getmessage());
                }
            }
            else
            {
                try
                {
                    params = algorithmparameters.getinstance("rc2", bouncycastleprovider.provider_name);
                    params.init(spec);
                }
                catch (exception e)
                {
                    throw new runtimeexception(e.getmessage());
                }
            }

            return params;
        }
    }

    public static class keygenerator
        extends basekeygenerator
    {
        public keygenerator()
        {
            super("rc2", 128, new cipherkeygenerator());
        }
    }

    public static class algparams
        extends basealgorithmparameters
    {
        private static final short[] table = {
            0xbd, 0x56, 0xea, 0xf2, 0xa2, 0xf1, 0xac, 0x2a, 0xb0, 0x93, 0xd1, 0x9c, 0x1b, 0x33, 0xfd, 0xd0,
            0x30, 0x04, 0xb6, 0xdc, 0x7d, 0xdf, 0x32, 0x4b, 0xf7, 0xcb, 0x45, 0x9b, 0x31, 0xbb, 0x21, 0x5a,
            0x41, 0x9f, 0xe1, 0xd9, 0x4a, 0x4d, 0x9e, 0xda, 0xa0, 0x68, 0x2c, 0xc3, 0x27, 0x5f, 0x80, 0x36,
            0x3e, 0xee, 0xfb, 0x95, 0x1a, 0xfe, 0xce, 0xa8, 0x34, 0xa9, 0x13, 0xf0, 0xa6, 0x3f, 0xd8, 0x0c,
            0x78, 0x24, 0xaf, 0x23, 0x52, 0xc1, 0x67, 0x17, 0xf5, 0x66, 0x90, 0xe7, 0xe8, 0x07, 0xb8, 0x60,
            0x48, 0xe6, 0x1e, 0x53, 0xf3, 0x92, 0xa4, 0x72, 0x8c, 0x08, 0x15, 0x6e, 0x86, 0x00, 0x84, 0xfa,
            0xf4, 0x7f, 0x8a, 0x42, 0x19, 0xf6, 0xdb, 0xcd, 0x14, 0x8d, 0x50, 0x12, 0xba, 0x3c, 0x06, 0x4e,
            0xec, 0xb3, 0x35, 0x11, 0xa1, 0x88, 0x8e, 0x2b, 0x94, 0x99, 0xb7, 0x71, 0x74, 0xd3, 0xe4, 0xbf,
            0x3a, 0xde, 0x96, 0x0e, 0xbc, 0x0a, 0xed, 0x77, 0xfc, 0x37, 0x6b, 0x03, 0x79, 0x89, 0x62, 0xc6,
            0xd7, 0xc0, 0xd2, 0x7c, 0x6a, 0x8b, 0x22, 0xa3, 0x5b, 0x05, 0x5d, 0x02, 0x75, 0xd5, 0x61, 0xe3,
            0x18, 0x8f, 0x55, 0x51, 0xad, 0x1f, 0x0b, 0x5e, 0x85, 0xe5, 0xc2, 0x57, 0x63, 0xca, 0x3d, 0x6c,
            0xb4, 0xc5, 0xcc, 0x70, 0xb2, 0x91, 0x59, 0x0d, 0x47, 0x20, 0xc8, 0x4f, 0x58, 0xe0, 0x01, 0xe2,
            0x16, 0x38, 0xc4, 0x6f, 0x3b, 0x0f, 0x65, 0x46, 0xbe, 0x7e, 0x2d, 0x7b, 0x82, 0xf9, 0x40, 0xb5,
            0x1d, 0x73, 0xf8, 0xeb, 0x26, 0xc7, 0x87, 0x97, 0x25, 0x54, 0xb1, 0x28, 0xaa, 0x98, 0x9d, 0xa5,
            0x64, 0x6d, 0x7a, 0xd4, 0x10, 0x81, 0x44, 0xef, 0x49, 0xd6, 0xae, 0x2e, 0xdd, 0x76, 0x5c, 0x2f,
            0xa7, 0x1c, 0xc9, 0x09, 0x69, 0x9a, 0x83, 0xcf, 0x29, 0x39, 0xb9, 0xe9, 0x4c, 0xff, 0x43, 0xab
        };

        private static final short[] ekb = {
            0x5d, 0xbe, 0x9b, 0x8b, 0x11, 0x99, 0x6e, 0x4d, 0x59, 0xf3, 0x85, 0xa6, 0x3f, 0xb7, 0x83, 0xc5,
            0xe4, 0x73, 0x6b, 0x3a, 0x68, 0x5a, 0xc0, 0x47, 0xa0, 0x64, 0x34, 0x0c, 0xf1, 0xd0, 0x52, 0xa5,
            0xb9, 0x1e, 0x96, 0x43, 0x41, 0xd8, 0xd4, 0x2c, 0xdb, 0xf8, 0x07, 0x77, 0x2a, 0xca, 0xeb, 0xef,
            0x10, 0x1c, 0x16, 0x0d, 0x38, 0x72, 0x2f, 0x89, 0xc1, 0xf9, 0x80, 0xc4, 0x6d, 0xae, 0x30, 0x3d,
            0xce, 0x20, 0x63, 0xfe, 0xe6, 0x1a, 0xc7, 0xb8, 0x50, 0xe8, 0x24, 0x17, 0xfc, 0x25, 0x6f, 0xbb,
            0x6a, 0xa3, 0x44, 0x53, 0xd9, 0xa2, 0x01, 0xab, 0xbc, 0xb6, 0x1f, 0x98, 0xee, 0x9a, 0xa7, 0x2d,
            0x4f, 0x9e, 0x8e, 0xac, 0xe0, 0xc6, 0x49, 0x46, 0x29, 0xf4, 0x94, 0x8a, 0xaf, 0xe1, 0x5b, 0xc3,
            0xb3, 0x7b, 0x57, 0xd1, 0x7c, 0x9c, 0xed, 0x87, 0x40, 0x8c, 0xe2, 0xcb, 0x93, 0x14, 0xc9, 0x61,
            0x2e, 0xe5, 0xcc, 0xf6, 0x5e, 0xa8, 0x5c, 0xd6, 0x75, 0x8d, 0x62, 0x95, 0x58, 0x69, 0x76, 0xa1,
            0x4a, 0xb5, 0x55, 0x09, 0x78, 0x33, 0x82, 0xd7, 0xdd, 0x79, 0xf5, 0x1b, 0x0b, 0xde, 0x26, 0x21,
            0x28, 0x74, 0x04, 0x97, 0x56, 0xdf, 0x3c, 0xf0, 0x37, 0x39, 0xdc, 0xff, 0x06, 0xa4, 0xea, 0x42,
            0x08, 0xda, 0xb4, 0x71, 0xb0, 0xcf, 0x12, 0x7a, 0x4e, 0xfa, 0x6c, 0x1d, 0x84, 0x00, 0xc8, 0x7f,
            0x91, 0x45, 0xaa, 0x2b, 0xc2, 0xb1, 0x8f, 0xd5, 0xba, 0xf2, 0xad, 0x19, 0xb2, 0x67, 0x36, 0xf7,
            0x0f, 0x0a, 0x92, 0x7d, 0xe3, 0x9d, 0xe9, 0x90, 0x3e, 0x23, 0x27, 0x66, 0x13, 0xec, 0x81, 0x15,
            0xbd, 0x22, 0xbf, 0x9f, 0x7e, 0xa9, 0x51, 0x4b, 0x4c, 0xfb, 0x02, 0xd3, 0x70, 0x86, 0x31, 0xe7,
            0x3b, 0x05, 0x03, 0x54, 0x60, 0x48, 0x65, 0x18, 0xd2, 0xcd, 0x5f, 0x32, 0x88, 0x0e, 0x35, 0xfd
        };

        private byte[] iv;
        private int parameterversion = 58;

        protected byte[] enginegetencoded()
        {
            return arrays.clone(iv);
        }

        protected byte[] enginegetencoded(
            string format)
            throws ioexception
        {
            if (this.isasn1formatstring(format))
            {
                if (parameterversion == -1)
                {
                    return new rc2cbcparameter(enginegetencoded()).getencoded();
                }
                else
                {
                    return new rc2cbcparameter(parameterversion, enginegetencoded()).getencoded();
                }
            }

            if (format.equals("raw"))
            {
                return enginegetencoded();
            }

            return null;
        }

        protected algorithmparameterspec localenginegetparameterspec(
            class paramspec)
            throws invalidparameterspecexception
        {
            if (paramspec == rc2parameterspec.class)
            {
                if (parameterversion != -1)
                {
                    if (parameterversion < 256)
                    {
                        return new rc2parameterspec(ekb[parameterversion], iv);
                    }
                    else
                    {
                        return new rc2parameterspec(parameterversion, iv);
                    }
                }
            }

            if (paramspec == ivparameterspec.class)
            {
                return new ivparameterspec(iv);
            }

            throw new invalidparameterspecexception("unknown parameter spec passed to rc2 parameters object.");
        }

        protected void engineinit(
            algorithmparameterspec paramspec)
            throws invalidparameterspecexception
        {
            if (paramspec instanceof ivparameterspec)
            {
                this.iv = ((ivparameterspec)paramspec).getiv();
            }
            else if (paramspec instanceof rc2parameterspec)
            {
                int effkeybits = ((rc2parameterspec)paramspec).geteffectivekeybits();
                if (effkeybits != -1)
                {
                    if (effkeybits < 256)
                    {
                        parameterversion = table[effkeybits];
                    }
                    else
                    {
                        parameterversion = effkeybits;
                    }
                }

                this.iv = ((rc2parameterspec)paramspec).getiv();
            }
            else
            {
                throw new invalidparameterspecexception("ivparameterspec or rc2parameterspec required to initialise a rc2 parameters algorithm parameters object");
            }
        }

        protected void engineinit(
            byte[] params)
            throws ioexception
        {
            this.iv = arrays.clone(params);
        }

        protected void engineinit(
            byte[] params,
            string format)
            throws ioexception
        {
            if (this.isasn1formatstring(format))
            {
                rc2cbcparameter p = rc2cbcparameter.getinstance(asn1primitive.frombytearray(params));

                if (p.getrc2parameterversion() != null)
                {
                    parameterversion = p.getrc2parameterversion().intvalue();
                }

                iv = p.getiv();

                return;
            }

            if (format.equals("raw"))
            {
                engineinit(params);
                return;
            }

            throw new ioexception("unknown parameters format in iv parameters object");
        }

        protected string enginetostring()
        {
            return "rc2 parameters";
        }
    }

    public static class mappings
        extends algorithmprovider
    {
        private static final string prefix = rc2.class.getname();

        public mappings()
        {
        }

        public void configure(configurableprovider provider)
        {

            provider.addalgorithm("algorithmparametergenerator.rc2", prefix + "$algparamgen");
            provider.addalgorithm("algorithmparametergenerator.1.2.840.113549.3.2", prefix + "$algparamgen");

            provider.addalgorithm("keygenerator.rc2", prefix + "$keygenerator");
            provider.addalgorithm("keygenerator.1.2.840.113549.3.2", prefix + "$keygenerator");

            provider.addalgorithm("algorithmparameters.rc2", prefix + "$algparams");
            provider.addalgorithm("algorithmparameters.1.2.840.113549.3.2", prefix + "$algparams");

            provider.addalgorithm("cipher.rc2", prefix + "$ecb");
            provider.addalgorithm("cipher.rc2wrap", prefix + "$wrap");
            provider.addalgorithm("alg.alias.cipher." + pkcsobjectidentifiers.id_alg_cmsrc2wrap, "rc2wrap");
            provider.addalgorithm("cipher.1.2.840.113549.3.2", prefix + "$cbc");

            provider.addalgorithm("mac.rc2mac", prefix + "$cbcmac");
            provider.addalgorithm("alg.alias.mac.rc2", "rc2mac");
            provider.addalgorithm("mac.rc2mac/cfb8", prefix + "$cfb8mac");
            provider.addalgorithm("alg.alias.mac.rc2/cfb8", "rc2mac/cfb8");

            provider.addalgorithm("alg.alias.secretkeyfactory.pbewithmd2andrc2-cbc", "pbewithmd2andrc2");

            provider.addalgorithm("alg.alias.secretkeyfactory.pbewithmd5andrc2-cbc", "pbewithmd5andrc2");

            provider.addalgorithm("alg.alias.secretkeyfactory.pbewithsha1andrc2-cbc", "pbewithsha1andrc2");

            provider.addalgorithm("alg.alias.secretkeyfactory." + pkcsobjectidentifiers.pbewithmd2andrc2_cbc, "pbewithmd2andrc2");

            provider.addalgorithm("alg.alias.secretkeyfactory." + pkcsobjectidentifiers.pbewithmd5andrc2_cbc, "pbewithmd5andrc2");

            provider.addalgorithm("alg.alias.secretkeyfactory." + pkcsobjectidentifiers.pbewithsha1andrc2_cbc, "pbewithsha1andrc2");
            provider.addalgorithm("alg.alias.secretkeyfactory.1.2.840.113549.1.12.1.5", "pbewithshaand128bitrc2-cbc");
            provider.addalgorithm("alg.alias.secretkeyfactory.1.2.840.113549.1.12.1.6", "pbewithshaand40bitrc2-cbc");

            provider.addalgorithm("secretkeyfactory.pbewithmd2andrc2", prefix + "$pbewithmd2keyfactory");
            provider.addalgorithm("secretkeyfactory.pbewithmd5andrc2", prefix + "$pbewithmd5keyfactory");
            provider.addalgorithm("secretkeyfactory.pbewithsha1andrc2", prefix + "$pbewithsha1keyfactory");

            provider.addalgorithm("secretkeyfactory.pbewithshaand128bitrc2-cbc", prefix + "$pbewithshaand128bitkeyfactory");
            provider.addalgorithm("secretkeyfactory.pbewithshaand40bitrc2-cbc", prefix + "$pbewithshaand40bitkeyfactory");
            
            provider.addalgorithm("alg.alias.cipher." + pkcsobjectidentifiers.pbewithmd2andrc2_cbc, "pbewithmd2andrc2");

            provider.addalgorithm("alg.alias.cipher." + pkcsobjectidentifiers.pbewithmd5andrc2_cbc, "pbewithmd5andrc2");

            provider.addalgorithm("alg.alias.cipher." + pkcsobjectidentifiers.pbewithsha1andrc2_cbc, "pbewithsha1andrc2");

            provider.addalgorithm("alg.alias.algorithmparameters.1.2.840.113549.1.12.1.5", "pkcs12pbe");
            provider.addalgorithm("alg.alias.algorithmparameters.1.2.840.113549.1.12.1.6", "pkcs12pbe");
            provider.addalgorithm("alg.alias.algorithmparameters.pbewithshaand3keytripledes", "pkcs12pbe");

            provider.addalgorithm("alg.alias.cipher.1.2.840.113549.1.12.1.5", "pbewithshaand128bitrc2-cbc");
            provider.addalgorithm("alg.alias.cipher.1.2.840.113549.1.12.1.6", "pbewithshaand40bitrc2-cbc");
            provider.addalgorithm("alg.alias.cipher.pbewithsha1and128bitrc2-cbc", "pbewithshaand128bitrc2-cbc");
            provider.addalgorithm("alg.alias.cipher.pbewithsha1and40bitrc2-cbc", "pbewithshaand40bitrc2-cbc");
            provider.addalgorithm("cipher.pbewithsha1andrc2", prefix + "$pbewithsha1andrc2");

            provider.addalgorithm("cipher.pbewithshaand128bitrc2-cbc", prefix + "$pbewithshaand128bitrc2");
            provider.addalgorithm("cipher.pbewithshaand40bitrc2-cbc", prefix + "$pbewithshaand40bitrc2");
            provider.addalgorithm("cipher.pbewithmd5andrc2", prefix + "$pbewithmd5andrc2");

            provider.addalgorithm("alg.alias.algorithmparameters.pbewithsha1andrc2", "pkcs12pbe");
            provider.addalgorithm("alg.alias.algorithmparameters.pbewithshaandrc2", "pkcs12pbe");
            provider.addalgorithm("alg.alias.algorithmparameters.pbewithsha1andrc2-cbc", "pkcs12pbe");
            provider.addalgorithm("alg.alias.algorithmparameters.pbewithshaand40bitrc2-cbc", "pkcs12pbe");
            provider.addalgorithm("alg.alias.algorithmparameters.pbewithshaand128bitrc2-cbc", "pkcs12pbe");
        }
    }
}
