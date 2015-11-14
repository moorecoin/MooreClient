package org.ripple.bouncycastle.jcajce.provider.symmetric;

import org.ripple.bouncycastle.crypto.cipherkeygenerator;
import org.ripple.bouncycastle.crypto.engines.blowfishengine;
import org.ripple.bouncycastle.crypto.modes.cbcblockcipher;
import org.ripple.bouncycastle.jcajce.provider.config.configurableprovider;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.baseblockcipher;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.basekeygenerator;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.ivalgorithmparameters;
import org.ripple.bouncycastle.jcajce.provider.util.algorithmprovider;

public final class blowfish
{
    private blowfish()
    {
    }
    
    public static class ecb
        extends baseblockcipher
    {
        public ecb()
        {
            super(new blowfishengine());
        }
    }

    public static class cbc
        extends baseblockcipher
    {
        public cbc()
        {
            super(new cbcblockcipher(new blowfishengine()), 64);
        }
    }

    public static class keygen
        extends basekeygenerator
    {
        public keygen()
        {
            super("blowfish", 128, new cipherkeygenerator());
        }
    }

    public static class algparams
        extends ivalgorithmparameters
    {
        protected string enginetostring()
        {
            return "blowfish iv";
        }
    }

    public static class mappings
        extends algorithmprovider
    {
        private static final string prefix = blowfish.class.getname();

        public mappings()
        {
        }

        public void configure(configurableprovider provider)
        {

            provider.addalgorithm("cipher.blowfish", prefix + "$ecb");
            provider.addalgorithm("cipher.1.3.6.1.4.1.3029.1.2", prefix + "$cbc");
            provider.addalgorithm("keygenerator.blowfish", prefix + "$keygen");
            provider.addalgorithm("alg.alias.keygenerator.1.3.6.1.4.1.3029.1.2", "blowfish");
            provider.addalgorithm("algorithmparameters.blowfish", prefix + "$algparams");
            provider.addalgorithm("alg.alias.algorithmparameters.1.3.6.1.4.1.3029.1.2", "blowfish");

        }
    }
}
