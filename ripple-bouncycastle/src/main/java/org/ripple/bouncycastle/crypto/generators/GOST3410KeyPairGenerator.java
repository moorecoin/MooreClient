package org.ripple.bouncycastle.crypto.generators;

import org.ripple.bouncycastle.crypto.asymmetriccipherkeypair;
import org.ripple.bouncycastle.crypto.asymmetriccipherkeypairgenerator;
import org.ripple.bouncycastle.crypto.keygenerationparameters;
import org.ripple.bouncycastle.crypto.params.gost3410keygenerationparameters;
import org.ripple.bouncycastle.crypto.params.gost3410parameters;
import org.ripple.bouncycastle.crypto.params.gost3410privatekeyparameters;
import org.ripple.bouncycastle.crypto.params.gost3410publickeyparameters;

import java.math.biginteger;
import java.security.securerandom;

/**
 * a gost3410 key pair generator.
 * this generates gost3410 keys in line with the method described
 * in gost r 34.10-94.
 */
public class gost3410keypairgenerator
        implements asymmetriccipherkeypairgenerator
    {
        private static final biginteger zero = biginteger.valueof(0);

        private gost3410keygenerationparameters param;

        public void init(
            keygenerationparameters param)
        {
            this.param = (gost3410keygenerationparameters)param;
        }

        public asymmetriccipherkeypair generatekeypair()
        {
            biginteger      p, q, a, x, y;
            gost3410parameters   gost3410params = param.getparameters();
            securerandom    random = param.getrandom();

            q = gost3410params.getq();
            p = gost3410params.getp();
            a = gost3410params.geta();

            do
            {
                x = new biginteger(256, random);
            }
            while (x.equals(zero) || x.compareto(q) >= 0);

            //
            // calculate the public key.
            //
            y = a.modpow(x, p);

            return new asymmetriccipherkeypair(
                    new gost3410publickeyparameters(y, gost3410params),
                    new gost3410privatekeyparameters(x, gost3410params));
        }
    }
