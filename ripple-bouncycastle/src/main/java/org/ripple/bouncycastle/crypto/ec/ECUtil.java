package org.ripple.bouncycastle.crypto.ec;

import java.math.biginteger;
import java.security.securerandom;

import org.ripple.bouncycastle.math.ec.ecconstants;

class ecutil
{
    static biginteger generatek(biginteger n, securerandom random)
    {
        int                    nbitlength = n.bitlength();
        biginteger             k = new biginteger(nbitlength, random);

        while (k.equals(ecconstants.zero) || (k.compareto(n) >= 0))
        {
            k = new biginteger(nbitlength, random);
        }

        return k;
    }
}
