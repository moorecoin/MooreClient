package org.ripple.bouncycastle.crypto.signers;

import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.dsa;
import org.ripple.bouncycastle.crypto.params.*;

import java.security.securerandom;
import java.math.biginteger;

/**
 * gost r 34.10-94 signature algorithm
 */
public class gost3410signer
        implements dsa
{
        gost3410keyparameters key;

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
                    this.key = (gost3410privatekeyparameters)rparam.getparameters();
                }
                else
                {
                    this.random = new securerandom();
                    this.key = (gost3410privatekeyparameters)param;
                }
            }
            else
            {
                this.key = (gost3410publickeyparameters)param;
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
            
            biginteger      m = new biginteger(1, mrev);
            gost3410parameters   params = key.getparameters();
            biginteger      k;

            do
            {
                k = new biginteger(params.getq().bitlength(), random);
            }
            while (k.compareto(params.getq()) >= 0);

            biginteger  r = params.geta().modpow(k, params.getp()).mod(params.getq());

            biginteger  s = k.multiply(m).
                                add(((gost3410privatekeyparameters)key).getx().multiply(r)).
                                    mod(params.getq());

            biginteger[]  res = new biginteger[2];

            res[0] = r;
            res[1] = s;

            return res;
        }

        /**
         * return true if the value r and s represent a gost3410 signature for
         * the passed in message for standard gost3410 the message should be a
         * gost3411 hash of the real message to be verified.
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
            
            biginteger           m = new biginteger(1, mrev);
            gost3410parameters   params = key.getparameters();
            biginteger           zero = biginteger.valueof(0);

            if (zero.compareto(r) >= 0 || params.getq().compareto(r) <= 0)
            {
                return false;
            }

            if (zero.compareto(s) >= 0 || params.getq().compareto(s) <= 0)
            {
                return false;
            }

            biginteger  v = m.modpow(params.getq().subtract(new biginteger("2")),params.getq());

            biginteger  z1 = s.multiply(v).mod(params.getq());
            biginteger  z2 = (params.getq().subtract(r)).multiply(v).mod(params.getq());
            
            z1 = params.geta().modpow(z1, params.getp());
            z2 = ((gost3410publickeyparameters)key).gety().modpow(z2, params.getp());

            biginteger  u = z1.multiply(z2).mod(params.getp()).mod(params.getq());

            return u.equals(r);
        }
}
