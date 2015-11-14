package org.ripple.bouncycastle.crypto.generators;

import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.params.parameterswithrandom;
import org.ripple.bouncycastle.crypto.params.rsakeyparameters;
import org.ripple.bouncycastle.crypto.params.rsaprivatecrtkeyparameters;

import java.math.biginteger;
import java.security.securerandom;

/**
 * generate a random factor suitable for use with rsa blind signatures
 * as outlined in chaum's blinding and unblinding as outlined in
 * "handbook of applied cryptography", page 475.
 */
public class rsablindingfactorgenerator
{
    private static biginteger zero = biginteger.valueof(0);
    private static biginteger one = biginteger.valueof(1);

    private rsakeyparameters key;
    private securerandom random;

    /**
     * initialise the factor generator
     *
     * @param param the necessary rsa key parameters.
     */
    public void init(
        cipherparameters param)
    {
        if (param instanceof parameterswithrandom)
        {
            parameterswithrandom rparam = (parameterswithrandom)param;

            key = (rsakeyparameters)rparam.getparameters();
            random = rparam.getrandom();
        }
        else
        {
            key = (rsakeyparameters)param;
            random = new securerandom();
        }

        if (key instanceof rsaprivatecrtkeyparameters)
        {
            throw new illegalargumentexception("generator requires rsa public key");
        }
    }

    /**
     * generate a suitable blind factor for the public key the generator was initialised with.
     *
     * @return a random blind factor
     */
    public biginteger generateblindingfactor()
    {
        if (key == null)
        {
            throw new illegalstateexception("generator not initialised");
        }

        biginteger m = key.getmodulus();
        int length = m.bitlength() - 1; // must be less than m.bitlength()
        biginteger factor;
        biginteger gcd;

        do
        {
            factor = new biginteger(length, random);
            gcd = factor.gcd(m);
        }
        while (factor.equals(zero) || factor.equals(one) || !gcd.equals(one));

        return factor;
    }
}
