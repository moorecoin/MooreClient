package org.ripple.bouncycastle.crypto.signers;

import java.math.biginteger;
import java.security.securerandom;

import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.dsa;
import org.ripple.bouncycastle.crypto.params.eckeyparameters;
import org.ripple.bouncycastle.crypto.params.ecprivatekeyparameters;
import org.ripple.bouncycastle.crypto.params.ecpublickeyparameters;
import org.ripple.bouncycastle.crypto.params.parameterswithrandom;
import org.ripple.bouncycastle.math.ec.ecalgorithms;
import org.ripple.bouncycastle.math.ec.ecconstants;
import org.ripple.bouncycastle.math.ec.ecpoint;

/**
 * ec-dsa as described in x9.62
 */
public class ecdsasigner
    implements ecconstants, dsa
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

    // 5.3 pg 28
    /**
     * generate a signature for the given message using the key we were
     * initialised with. for conventional dsa the message should be a sha-1
     * hash of the message of interest.
     *
     * @param message the message that will be verified later.
     */
    public biginteger[] generatesignature(
        byte[] message)
    {
        biginteger n = key.getparameters().getn();
        biginteger e = calculatee(n, message);
        biginteger r = null;
        biginteger s = null;

        // 5.3.2
        do // generate s
        {
            biginteger k = null;
            int        nbitlength = n.bitlength();

            do // generate r
            {
                do
                {
                    k = new biginteger(nbitlength, random);
                }
                while (k.equals(zero) || k.compareto(n) >= 0);

                ecpoint p = key.getparameters().getg().multiply(k);

                // 5.3.3
                biginteger x = p.getx().tobiginteger();

                r = x.mod(n);
            }
            while (r.equals(zero));

            biginteger d = ((ecprivatekeyparameters)key).getd();

            s = k.modinverse(n).multiply(e.add(d.multiply(r))).mod(n);
        }
        while (s.equals(zero));

        biginteger[]  res = new biginteger[2];

        res[0] = r;
        res[1] = s;

        return res;
    }

    // 5.4 pg 29
    /**
     * return true if the value r and s represent a dsa signature for
     * the passed in message (for standard dsa the message should be
     * a sha-1 hash of the real message to be verified).
     */
    public boolean verifysignature(
        byte[]      message,
        biginteger  r,
        biginteger  s)
    {
        biginteger n = key.getparameters().getn();
        biginteger e = calculatee(n, message);

        // r in the range [1,n-1]
        if (r.compareto(one) < 0 || r.compareto(n) >= 0)
        {
            return false;
        }

        // s in the range [1,n-1]
        if (s.compareto(one) < 0 || s.compareto(n) >= 0)
        {
            return false;
        }

        biginteger c = s.modinverse(n);

        biginteger u1 = e.multiply(c).mod(n);
        biginteger u2 = r.multiply(c).mod(n);

        ecpoint g = key.getparameters().getg();
        ecpoint q = ((ecpublickeyparameters)key).getq();

        ecpoint point = ecalgorithms.sumoftwomultiplies(g, u1, q, u2);

        // components must be bogus.
        if (point.isinfinity())
        {
            return false;
        }

        biginteger v = point.getx().tobiginteger().mod(n);

        return v.equals(r);
    }

    private biginteger calculatee(biginteger n, byte[] message)
    {
        int log2n = n.bitlength();
        int messagebitlength = message.length * 8;

        if (log2n >= messagebitlength)
        {
            return new biginteger(1, message);
        }
        else
        {
            biginteger trunc = new biginteger(1, message);

            trunc = trunc.shiftright(messagebitlength - log2n);

            return trunc;
        }
    }
}
