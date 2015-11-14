package org.ripple.bouncycastle.pqc.math.linearalgebra;

import java.security.securerandom;

public class randutils
{
    static int nextint(securerandom rand, int n)
    {

        if ((n & -n) == n)  // i.e., n is a power of 2
        {
            return (int)((n * (long)(rand.nextint() >>> 1)) >> 31);
        }

        int bits, value;
        do
        {
            bits = rand.nextint() >>> 1;
            value = bits % n;
        }
        while (bits - value + (n - 1) < 0);

        return value;
    }
}
