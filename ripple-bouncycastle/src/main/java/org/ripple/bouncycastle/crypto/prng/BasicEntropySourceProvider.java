package org.ripple.bouncycastle.crypto.prng;

import java.security.securerandom;

/**
 * an entropysourceprovider where entropy generation is based on a securerandom output using securerandom.generateseed().
 */
public class basicentropysourceprovider
    implements entropysourceprovider
{
    private final securerandom _sr;
    private final boolean      _predictionresistant;

    /**
     * create a entropy source provider based on the passed in securerandom.
     *
     * @param random the securerandom to base entropysource construction on.
     * @param ispredictionresistant boolean indicating if the securerandom is based on prediction resistant entropy or not (true if it is).
     */
    public basicentropysourceprovider(securerandom random, boolean ispredictionresistant)
    {
        _sr = random;
        _predictionresistant = ispredictionresistant;
    }

    /**
     * return an entropy source that will create bitsrequired bits of entropy on
     * each invocation of getentropy().
     *
     * @param bitsrequired size (in bits) of entropy to be created by the provided source.
     * @return an entropysource that generates bitsrequired bits of entropy on each call to its getentropy() method.
     */
    public entropysource get(final int bitsrequired)
    {
        return new entropysource()
        {
            public boolean ispredictionresistant()
            {
                return _predictionresistant;
            }

            public byte[] getentropy()
            {
                return _sr.generateseed((bitsrequired + 7) / 8);
            }

            public int entropysize()
            {
                return bitsrequired;
            }
        };
    }
}
