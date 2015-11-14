package org.ripple.bouncycastle.crypto.generators;

import org.ripple.bouncycastle.crypto.params.dhparameters;

import java.math.biginteger;
import java.security.securerandom;

public class dhparametersgenerator
{
    private int             size;
    private int             certainty;
    private securerandom    random;

    private static final biginteger two = biginteger.valueof(2);

    /**
     * initialise the parameters generator.
     * 
     * @param size bit length for the prime p
     * @param certainty level of certainty for the prime number tests
     * @param random  a source of randomness
     */
    public void init(
        int             size,
        int             certainty,
        securerandom    random)
    {
        this.size = size;
        this.certainty = certainty;
        this.random = random;
    }

    /**
     * which generates the p and g values from the given parameters,
     * returning the dhparameters object.
     * <p>
     * note: can take a while...
     */
    public dhparameters generateparameters()
    {
        //
        // find a safe prime p where p = 2*q + 1, where p and q are prime.
        //
        biginteger[] safeprimes = dhparametershelper.generatesafeprimes(size, certainty, random);

        biginteger p = safeprimes[0];
        biginteger q = safeprimes[1];
        biginteger g = dhparametershelper.selectgenerator(p, q, random);

        return new dhparameters(p, g, q, two, null);
    }
}
