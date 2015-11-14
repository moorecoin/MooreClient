package org.ripple.bouncycastle.jcajce.provider.symmetric;

import org.ripple.bouncycastle.asn1.pkcs.pkcsobjectidentifiers;
import org.ripple.bouncycastle.crypto.cipherkeygenerator;
import org.ripple.bouncycastle.crypto.engines.rc4engine;
import org.ripple.bouncycastle.jcajce.provider.config.configurableprovider;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.basekeygenerator;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.basestreamcipher;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.pbesecretkeyfactory;
import org.ripple.bouncycastle.jcajce.provider.util.algorithmprovider;

public final class arc4
{
    private arc4()
    {
    }
    
    public static class base
        extends basestreamcipher
    {
        public base()
        {
            super(new rc4engine(), 0);
        }
    }

    public static class keygen
        extends basekeygenerator
    {
        public keygen()
        {
            super("rc4", 128, new cipherkeygenerator());
        }
    }

    /**
     * pbewithshaand128bitrc4
     */
    static public class pbewithshaand128bitkeyfactory
        extends pbesecretkeyfactory
    {
        public pbewithshaand128bitkeyfactory()
        {
            super("pbewithshaand128bitrc4", pkcsobjectidentifiers.pbewithshaand128bitrc4, true, pkcs12, sha1, 128, 0);
        }
    }

    /**
     * pbewithshaand40bitrc4
     */
    static public class pbewithshaand40bitkeyfactory
        extends pbesecretkeyfactory
    {
        public pbewithshaand40bitkeyfactory()
        {
            super("pbewithshaand128bitrc4", pkcsobjectidentifiers.pbewithshaand128bitrc4, true, pkcs12, sha1, 40, 0);
        }
    }


    /**
     * pbewithshaand128bitrc4
     */
    static public class pbewithshaand128bit
        extends basestreamcipher
    {
        public pbewithshaand128bit()
        {
            super(new rc4engine(), 0);
        }
    }

    /**
     * pbewithshaand40bitrc4
     */
    static public class pbewithshaand40bit
        extends basestreamcipher
    {
        public pbewithshaand40bit()
        {
            super(new rc4engine(), 0);
        }
    }

    public static class mappings
        extends algorithmprovider
    {
        private static final string prefix = arc4.class.getname();

        public mappings()
        {
        }

        public void configure(configurableprovider provider)
        {
            provider.addalgorithm("cipher.arc4", prefix + "$base");
            provider.addalgorithm("alg.alias.cipher." + pkcsobjectidentifiers.rc4, "arc4");
            provider.addalgorithm("alg.alias.cipher.arcfour", "arc4");
            provider.addalgorithm("alg.alias.cipher.rc4", "arc4");
            provider.addalgorithm("keygenerator.arc4", prefix + "$keygen");
            provider.addalgorithm("alg.alias.keygenerator.rc4", "arc4");
            provider.addalgorithm("alg.alias.keygenerator.1.2.840.113549.3.4", "arc4");
            provider.addalgorithm("secretkeyfactory.pbewithshaand128bitrc4", prefix + "$pbewithshaand128bitkeyfactory");
            provider.addalgorithm("secretkeyfactory.pbewithshaand40bitrc4", prefix + "$pbewithshaand40bitkeyfactory");

            provider.addalgorithm("alg.alias.algorithmparameters." + pkcsobjectidentifiers.pbewithshaand128bitrc4, "pkcs12pbe");
            provider.addalgorithm("alg.alias.algorithmparameters." + pkcsobjectidentifiers.pbewithshaand40bitrc4, "pkcs12pbe");
            provider.addalgorithm("alg.alias.algorithmparameters.pbewithshaand40bitrc4", "pkcs12pbe");
            provider.addalgorithm("alg.alias.algorithmparameters.pbewithshaand128bitrc4", "pkcs12pbe");
            provider.addalgorithm("alg.alias.algorithmparameters.pbewithshaandrc4", "pkcs12pbe");
            provider.addalgorithm("cipher.pbewithshaand128bitrc4", prefix + "$pbewithshaand128bit");
            provider.addalgorithm("cipher.pbewithshaand40bitrc4", prefix + "$pbewithshaand40bit");

            provider.addalgorithm("alg.alias.secretkeyfactory." + pkcsobjectidentifiers.pbewithshaand128bitrc4, "pbewithshaand128bitrc4");
            provider.addalgorithm("alg.alias.secretkeyfactory." + pkcsobjectidentifiers.pbewithshaand40bitrc4, "pbewithshaand40bitrc4");

            provider.addalgorithm("alg.alias.cipher.pbewithsha1and128bitrc4", "pbewithshaand128bitrc4");
            provider.addalgorithm("alg.alias.cipher.pbewithsha1and40bitrc4", "pbewithshaand40bitrc4");

            provider.addalgorithm("alg.alias.cipher." + pkcsobjectidentifiers.pbewithshaand128bitrc4, "pbewithshaand128bitrc4");
            provider.addalgorithm("alg.alias.cipher." + pkcsobjectidentifiers.pbewithshaand40bitrc4, "pbewithshaand40bitrc4");
        }
    }
}
