package org.ripple.bouncycastle.crypto;

import java.security.securerandom;

/**
 * the base class for parameters to key generators.
 */
public class keygenerationparameters
{
    private securerandom    random;
    private int             strength;

    /**
     * initialise the generator with a source of randomness
     * and a strength (in bits).
     *
     * @param random the random byte source.
     * @param strength the size, in bits, of the keys we want to produce.
     */
    public keygenerationparameters(
        securerandom    random,
        int             strength)
    {
        this.random = random;
        this.strength = strength;
    }

    /**
     * return the random source associated with this
     * generator.
     *
     * @return the generators random source.
     */
    public securerandom getrandom()
    {
        return random;
    }

    /**
     * return the bit strength for keys produced by this generator,
     *
     * @return the strength of the keys this generator produces (in bits).
     */
    public int getstrength()
    {
        return strength;
    }
}
