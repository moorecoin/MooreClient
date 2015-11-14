package org.ripple.bouncycastle.crypto.generators;

import java.math.biginteger;
import java.security.securerandom;

import org.ripple.bouncycastle.crypto.params.dhparameters;
import org.ripple.bouncycastle.util.bigintegers;

class dhkeygeneratorhelper
{
    static final dhkeygeneratorhelper instance = new dhkeygeneratorhelper();

    private static final biginteger one = biginteger.valueof(1);
    private static final biginteger two = biginteger.valueof(2);

    private dhkeygeneratorhelper()
    {
    }

    biginteger calculateprivate(dhparameters dhparams, securerandom random)
    {
        biginteger p = dhparams.getp();
        int limit = dhparams.getl();

        if (limit != 0)
        {
            return new biginteger(limit, random).setbit(limit - 1);
        }

        biginteger min = two;
        int m = dhparams.getm();
        if (m != 0)
        {
            min = one.shiftleft(m - 1);
        }

        biginteger max = p.subtract(two);
        biginteger q = dhparams.getq();
        if (q != null)
        {
            max = q.subtract(two);
        }

        return bigintegers.createrandominrange(min, max, random);
    }

    biginteger calculatepublic(dhparameters dhparams, biginteger x)
    {
        return dhparams.getg().modpow(x, dhparams.getp());
    }
}
