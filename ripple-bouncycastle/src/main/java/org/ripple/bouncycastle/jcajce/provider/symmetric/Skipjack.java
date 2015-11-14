package org.ripple.bouncycastle.jcajce.provider.symmetric;

import org.ripple.bouncycastle.crypto.cipherkeygenerator;
import org.ripple.bouncycastle.crypto.engines.skipjackengine;
import org.ripple.bouncycastle.crypto.macs.cbcblockciphermac;
import org.ripple.bouncycastle.crypto.macs.cfbblockciphermac;
import org.ripple.bouncycastle.jcajce.provider.config.configurableprovider;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.baseblockcipher;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.basekeygenerator;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.basemac;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.ivalgorithmparameters;
import org.ripple.bouncycastle.jcajce.provider.util.algorithmprovider;

public final class skipjack
{
    private skipjack()
    {
    }
    
    public static class ecb
        extends baseblockcipher
    {
        public ecb()
        {
            super(new skipjackengine());
        }
    }

    public static class keygen
        extends basekeygenerator
    {
        public keygen()
        {
            super("skipjack", 80, new cipherkeygenerator());
        }
    }

    public static class algparams
        extends ivalgorithmparameters
    {
        protected string enginetostring()
        {
            return "skipjack iv";
        }
    }

    public static class mac
        extends basemac
    {
        public mac()
        {
            super(new cbcblockciphermac(new skipjackengine()));
        }
    }

    public static class maccfb8
        extends basemac
    {
        public maccfb8()
        {
            super(new cfbblockciphermac(new skipjackengine()));
        }
    }

    public static class mappings
        extends algorithmprovider
    {
        private static final string prefix = skipjack.class.getname();

        public mappings()
        {
        }

        public void configure(configurableprovider provider)
        {

            provider.addalgorithm("cipher.skipjack", prefix + "$ecb");
            provider.addalgorithm("keygenerator.skipjack", prefix + "$keygen");
            provider.addalgorithm("algorithmparameters.skipjack", prefix + "$algparams");
            provider.addalgorithm("mac.skipjackmac", prefix + "$mac");
            provider.addalgorithm("alg.alias.mac.skipjack", "skipjackmac");
            provider.addalgorithm("mac.skipjackmac/cfb8", prefix + "$maccfb8");
            provider.addalgorithm("alg.alias.mac.skipjack/cfb8", "skipjackmac/cfb8");

        }
    }
}
