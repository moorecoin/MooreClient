package org.ripple.bouncycastle.crypto.signers;

import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.dsa;
import org.ripple.bouncycastle.crypto.params.dsakeyparameters;
import org.ripple.bouncycastle.crypto.params.dsaparameters;
import org.ripple.bouncycastle.crypto.params.dsaprivatekeyparameters;
import org.ripple.bouncycastle.crypto.params.dsapublickeyparameters;
import org.ripple.bouncycastle.crypto.params.parameterswithrandom;

import java.math.biginteger;
import java.security.securerandom;

/**
 * the digital signature algorithm - as described in "handbook of applied
 * cryptography", pages 452 - 453.
 */
public class dsasigner
    implements dsa
{
    dsakeyparameters key;

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
                this.key = (dsaprivatekeyparameters)rparam.getparameters();
            }
            else
            {
                this.random = new securerandom();
                this.key = (dsaprivatekeyparameters)param;
            }
        }
        else
        {
            this.key = (dsapublickeyparameters)param;
        }
    }

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
        dsaparameters   params = key.getparameters();
        biginteger      m = calculatee(params.getq(), message);
        biginteger      k;
        int                  qbitlength = params.getq().bitlength();

        do 
        {
            k = new biginteger(qbitlength, random);
        }
        while (k.compareto(params.getq()) >= 0);

        biginteger  r = params.getg().modpow(k, params.getp()).mod(params.getq());

        k = k.modinverse(params.getq()).multiply(
                    m.add(((dsaprivatekeyparameters)key).getx().multiply(r)));

        biginteger  s = k.mod(params.getq());

        biginteger[]  res = new biginteger[2];

        res[0] = r;
        res[1] = s;

        return res;
    }

    /**
     * return true if the value r and s represent a dsa signature for
     * the passed in message for standard dsa the message should be a
     * sha-1 hash of the real message to be verified.
     */
    public boolean verifysignature(
        byte[]      message,
        biginteger  r,
        biginteger  s)
    {
        dsaparameters   params = key.getparameters();
        biginteger      m = calculatee(params.getq(), message);
        biginteger      zero = biginteger.valueof(0);

        if (zero.compareto(r) >= 0 || params.getq().compareto(r) <= 0)
        {
            return false;
        }

        if (zero.compareto(s) >= 0 || params.getq().compareto(s) <= 0)
        {
            return false;
        }

        biginteger  w = s.modinverse(params.getq());

        biginteger  u1 = m.multiply(w).mod(params.getq());
        biginteger  u2 = r.multiply(w).mod(params.getq());

        u1 = params.getg().modpow(u1, params.getp());
        u2 = ((dsapublickeyparameters)key).gety().modpow(u2, params.getp());

        biginteger  v = u1.multiply(u2).mod(params.getp()).mod(params.getq());

        return v.equals(r);
    }

    private biginteger calculatee(biginteger n, byte[] message)
    {
        if (n.bitlength() >= message.length * 8)
        {
            return new biginteger(1, message);
        }
        else
        {
            byte[] trunc = new byte[n.bitlength() / 8];

            system.arraycopy(message, 0, trunc, 0, trunc.length);

            return new biginteger(1, trunc);
        }
    }
}
