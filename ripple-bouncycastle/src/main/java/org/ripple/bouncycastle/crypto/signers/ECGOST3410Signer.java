package org.ripple.bouncycastle.crypto.signers;

import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.dsa;
import org.ripple.bouncycastle.crypto.params.eckeyparameters;
import org.ripple.bouncycastle.crypto.params.ecprivatekeyparameters;
import org.ripple.bouncycastle.crypto.params.ecpublickeyparameters;
import org.ripple.bouncycastle.crypto.params.parameterswithrandom;
import org.ripple.bouncycastle.math.ec.ecalgorithms;
import org.ripple.bouncycastle.math.ec.ecconstants;
import org.ripple.bouncycastle.math.ec.ecpoint;

import java.math.biginteger;
import java.security.securerandom;

/**
 * gost r 34.10-2001 signature algorithm
 */
public class ecgost3410signer
    implements dsa
{
    eckeyparameters key;

    securerandom    random;

    public void init(
        boolean                 forsigning,
        cipherparameters        param)
    {
        if (forsigning)
        {
            if (param instanceof parameterswithrandom)
            {
                parameterswithrandom    rparam = (parameterswithrandom)param;

                this.random = rparam.getrandom();
                this.key = (ecprivatekeyparameters)rparam.getparameters();
            }
            else
            {
                this.random = new securerandom();
                this.key = (ecprivatekeyparameters)param;
            }
        }
        else
        {
            this.key = (ecpublickeyparameters)param;
        }
    }

    /**
     * generate a signature for the given message using the key we were
     * initialised with. for conventional gost3410 the message should be a gost3411
     * hash of the message of interest.
     *
     * @param message the message that will be verified later.
     */
    public biginteger[] generatesignature(
        byte[] message)
    {
        byte[] mrev = new byte[message.length]; // conversion is little-endian
        for (int i = 0; i != mrev.length; i++)
        {
            mrev[i] = message[mrev.length - 1 - i];
        }
        
        biginteger e = new biginteger(1, mrev);
        biginteger n = key.getparameters().getn();

        biginteger r = null;
        biginteger s = null;

        do // generate s
        {
            biginteger k = null;

            do // generate r
            {
                do
                {
                    k = new biginteger(n.bitlength(), random);
                }
                while (k.equals(ecconstants.zero));

                ecpoint p = key.getparameters().getg().multiply(k);

                biginteger x = p.getx().tobiginteger();

                r = x.mod(n);
            }
            while (r.equals(ecconstants.zero));

            biginteger d = ((ecprivatekeyparameters)key).getd();

            s = (k.multiply(e)).add(d.multiply(r)).mod(n);
        }
        while (s.equals(ecconstants.zero));

        biginteger[]  res = new biginteger[2];

        res[0] = r;
        res[1] = s;

        return res;
    }

    /**
     * return true if the value r and s represent a gost3410 signature for
     * the passed in message (for standard gost3410 the message should be
     * a gost3411 hash of the real message to be verified).
     */
    public boolean verifysignature(
        byte[]      message,
        biginteger  r,
        biginteger  s)
    {
        byte[] mrev = new byte[message.length]; // conversion is little-endian
        for (int i = 0; i != mrev.length; i++)
        {
            mrev[i] = message[mrev.length - 1 - i];
        }
        
        biginteger e = new biginteger(1, mrev);
        biginteger n = key.getparameters().getn();

        // r in the range [1,n-1]
        if (r.compareto(ecconstants.one) < 0 || r.compareto(n) >= 0)
        {
            return false;
        }

        // s in the range [1,n-1]
        if (s.compareto(ecconstants.one) < 0 || s.compareto(n) >= 0)
        {
            return false;
        }

        biginteger v = e.modinverse(n);

        biginteger z1 = s.multiply(v).mod(n);
        biginteger z2 = (n.subtract(r)).multiply(v).mod(n);

        ecpoint g = key.getparameters().getg(); // p
        ecpoint q = ((ecpublickeyparameters)key).getq();

        ecpoint point = ecalgorithms.sumoftwomultiplies(g, z1, q, z2);

        // components must be bogus.
        if (point.isinfinity())
        {
            return false;
        }

        biginteger r = point.getx().tobiginteger().mod(n);

        return r.equals(r);
    }
}
