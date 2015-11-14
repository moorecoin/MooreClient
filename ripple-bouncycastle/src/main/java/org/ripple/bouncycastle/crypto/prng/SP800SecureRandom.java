package org.ripple.bouncycastle.crypto.prng;

import java.security.securerandom;

import org.ripple.bouncycastle.crypto.prng.drbg.sp80090drbg;

public class sp800securerandom
    extends securerandom
{
    private final drbgprovider drbgprovider;
    private final boolean predictionresistant;
    private final securerandom randomsource;
    private final entropysource entropysource;

    private sp80090drbg drbg;

    sp800securerandom(securerandom randomsource, entropysource entropysource, drbgprovider drbgprovider, boolean predictionresistant)
    {
        this.randomsource = randomsource;
        this.entropysource = entropysource;
        this.drbgprovider = drbgprovider;
        this.predictionresistant = predictionresistant;
    }

    public void setseed(byte[] seed)
    {
        synchronized (this)
        {
            if (randomsource != null)
            {
                this.randomsource.setseed(seed);
            }
        }
    }

    public void setseed(long seed)
    {
        synchronized (this)
        {
            // this will happen when securerandom() is created
            if (randomsource != null)
            {
                this.randomsource.setseed(seed);
            }
        }
    }

    public void nextbytes(byte[] bytes)
    {
        synchronized (this)
        {
            if (drbg == null)
            {
                drbg = drbgprovider.get(entropysource);
            }

            // check if a reseed is required...
            if (drbg.generate(bytes, null, predictionresistant) < 0)
            {
                drbg.reseed(entropysource.getentropy());
                drbg.generate(bytes, null, predictionresistant);
            }
        }
    }

    public byte[] generateseed(int numbytes)
    {
        byte[] bytes = new byte[numbytes];

        this.nextbytes(bytes);

        return bytes;
    }
}
