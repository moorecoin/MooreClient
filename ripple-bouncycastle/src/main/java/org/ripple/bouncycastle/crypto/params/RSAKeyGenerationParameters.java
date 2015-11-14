package org.ripple.bouncycastle.crypto.params;

import java.math.biginteger;
import java.security.securerandom;

import org.ripple.bouncycastle.crypto.keygenerationparameters;

public class rsakeygenerationparameters
    extends keygenerationparameters
{
    private biginteger publicexponent;
    private int certainty;

    public rsakeygenerationparameters(
        biginteger      publicexponent,
        securerandom    random,
        int             strength,
        int             certainty)
    {
        super(random, strength);

        if (strength < 12)
        {
            throw new illegalargumentexception("key strength too small");
        }

        //
        // public exponent cannot be even
        //
        if (!publicexponent.testbit(0)) 
        {
                throw new illegalargumentexception("public exponent cannot be even");
        }
        
        this.publicexponent = publicexponent;
        this.certainty = certainty;
    }

    public biginteger getpublicexponent()
    {
        return publicexponent;
    }

    public int getcertainty()
    {
        return certainty;
    }
}
