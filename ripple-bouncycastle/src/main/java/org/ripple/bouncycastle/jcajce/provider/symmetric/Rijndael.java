package org.ripple.bouncycastle.jcajce.provider.symmetric;

import org.ripple.bouncycastle.crypto.blockcipher;
import org.ripple.bouncycastle.crypto.cipherkeygenerator;
import org.ripple.bouncycastle.crypto.engines.rijndaelengine;
import org.ripple.bouncycastle.jcajce.provider.config.configurableprovider;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.baseblockcipher;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.basekeygenerator;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.blockcipherprovider;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.ivalgorithmparameters;
import org.ripple.bouncycastle.jcajce.provider.util.algorithmprovider;

public final class rijndael
{
    private rijndael()
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
                    return new rijndaelengine();
                }
            });
        }
    }

    public static class keygen
        extends basekeygenerator
    {
        public keygen()
        {
            super("rijndael", 192, new cipherkeygenerator());
        }
    }

    public static class algparams
        extends ivalgorithmparameters
    {
        protected string enginetostring()
        {
            return "rijndael iv";
        }
    }

    public static class mappings
        extends algorithmprovider
    {
        private static final string prefix = rijndael.class.getname();

        public mappings()
        {
        }

        public void configure(configurableprovider provider)
        {

            provider.addalgorithm("cipher.rijndael", prefix + "$ecb");
            provider.addalgorithm("keygenerator.rijndael", prefix + "$keygen");
            provider.addalgorithm("algorithmparameters.rijndael", prefix + "$algparams");

        }
    }
}
