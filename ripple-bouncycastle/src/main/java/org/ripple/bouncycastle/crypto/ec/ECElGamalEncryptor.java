package org.ripple.bouncycastle.crypto.ec;

import java.math.biginteger;
import java.security.securerandom;

import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.params.ecpublickeyparameters;
import org.ripple.bouncycastle.crypto.params.parameterswithrandom;
import org.ripple.bouncycastle.math.ec.ecconstants;
import org.ripple.bouncycastle.math.ec.ecpoint;

/**
 * this does your basic elgamal encryption algorithm using ec
 */
public class ecelgamalencryptor
    implements ecencryptor
{
    private ecpublickeyparameters key;
    private securerandom          random;

    /**
     * initialise the encryptor.
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
                throw new illegalargumentexception("ecpublickeyparameters are required for encryption.");
            }
            this.key = (ecpublickeyparameters)p.getparameters();
            this.random = p.getrandom();
        }
        else
        {
            if (!(param instanceof ecpublickeyparameters))
            {
                throw new illegalargumentexception("ecpublickeyparameters are required for encryption.");
            }

            this.key = (ecpublickeyparameters)param;
            this.random = new securerandom();
        }
    }

    /**
     * process a single ec point using the basic elgamal algorithm.
     *
     * @param point the ec point to process.
     * @return the result of the elgamal process.
     */
    public ecpair encrypt(ecpoint point)
    {
        if (key == null)
        {
            throw new illegalstateexception("ecelgamalencryptor not initialised");
        }

        biginteger             n = key.getparameters().getn();
        biginteger             k = ecutil.generatek(n, random);

        ecpoint  g = key.getparameters().getg();
        ecpoint  gamma = g.multiply(k);
        ecpoint  phi = key.getq().multiply(k).add(point);

        return new ecpair(gamma, phi);
    }
}
