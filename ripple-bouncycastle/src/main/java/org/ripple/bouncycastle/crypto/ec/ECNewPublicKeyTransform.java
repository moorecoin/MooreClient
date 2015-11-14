package org.ripple.bouncycastle.crypto.ec;

import java.math.biginteger;
import java.security.securerandom;

import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.params.ecpublickeyparameters;
import org.ripple.bouncycastle.crypto.params.parameterswithrandom;
import org.ripple.bouncycastle.math.ec.ecpoint;

/**
 * this does your basic elgamal encryption algorithm using ec
 */
public class ecnewpublickeytransform
    implements ecpairtransform
{
    private ecpublickeyparameters key;
    private securerandom          random;

    /**
     * initialise the ec elgamal engine.
     *
     * @param param the necessary ec key parameters.
     */
    public void init(
        cipherparameters    param)
    {
        if (param instanceof parameterswithrandom)
        {
            parameterswithrandom    p = (parameterswithrandom)param;

            if (!(p.getparameters() instanceof ecpublickeyparameters))
            {
                throw new illegalargumentexception("ecpublickeyparameters are required for new public key transform.");
            }
            this.key = (ecpublickeyparameters)p.getparameters();
            this.random = p.getrandom();
        }
        else
        {
            if (!(param instanceof ecpublickeyparameters))
            {
                throw new illegalargumentexception("ecpublickeyparameters are required for new public key transform.");
            }

            this.key = (ecpublickeyparameters)param;
            this.random = new securerandom();
        }
    }

    /**
     * transform an existing cipher test pair using the elgamal algorithm. note: the input ciphertext will
     * need to be preserved in order to complete the transformation to the new public key.
     *
     * @param ciphertext the ec point to process.
     * @return returns a new ecpair representing the result of the process.
     */
    public ecpair transform(ecpair ciphertext)
    {
        if (key == null)
        {
            throw new illegalstateexception("ecnewpublickeytransform not initialised");
        }

        biginteger             n = key.getparameters().getn();
        biginteger             k = ecutil.generatek(n, random);

        ecpoint  g = key.getparameters().getg();
        ecpoint  gamma = g.multiply(k);
        ecpoint  phi = key.getq().multiply(k).add(ciphertext.gety());

        return new ecpair(gamma, phi);
    }
}
