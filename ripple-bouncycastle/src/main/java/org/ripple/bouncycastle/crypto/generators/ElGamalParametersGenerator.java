package org.ripple.bouncycastle.crypto.generators;

import org.ripple.bouncycastle.crypto.params.elgamalparameters;

import java.math.biginteger;
import java.security.securerandom;

public class elgamalparametersgenerator
{
    private int             size;
    private int             certainty;
    private securerandom    random;

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
     * returning the elgamalparameters object.
     * <p>
     * note: can take a while...
     */
    public elgamalparameters generateparameters()
    {
        //
        // find a safe prime p where p = 2*q + 1, where p and q are prime.
        //
        biginteger[] safeprimes = dhparametershelper.generatesafeprimes(size, certainty, random);

        biginteger p = safeprimes[0];
        biginteger q = safeprimes[1];
        biginteger g = dhparametershelper.selectgenerator(p, q, random);

        return new elgamalparameters(p, g);
    }
}
