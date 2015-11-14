package org.ripple.bouncycastle.crypto.generators;

import java.math.biginteger;
import java.security.securerandom;

import org.ripple.bouncycastle.util.bigintegers;

class dhparametershelper
{
    private static final biginteger one = biginteger.valueof(1);
    private static final biginteger two = biginteger.valueof(2);

    /*
     * finds a pair of prime biginteger's {p, q: p = 2q + 1}
     * 
     * (see: handbook of applied cryptography 4.86)
     */
    static biginteger[] generatesafeprimes(int size, int certainty, securerandom random)
    {
        biginteger p, q;
        int qlength = size - 1;

        for (;;)
        {
            q = new biginteger(qlength, 2, random);

            // p <- 2q + 1
            p = q.shiftleft(1).add(one);

            if (p.isprobableprime(certainty) && (certainty <= 2 || q.isprobableprime(certainty)))
            {
                break;
            }
        }

        return new biginteger[] { p, q };
    }

    /*
     * select a high order element of the multiplicative group zp*
     * 
     * p and q must be s.t. p = 2*q + 1, where p and q are prime (see generatesafeprimes)
     */
    static biginteger selectgenerator(biginteger p, biginteger q, securerandom random)
    {
        biginteger pminustwo = p.subtract(two);
        biginteger g;

        /*
         * (see: handbook of applied cryptography 4.80)
         */
//        do
//        {
//            g = bigintegers.createrandominrange(two, pminustwo, random);
//        }
//        while (g.modpow(two, p).equals(one) || g.modpow(q, p).equals(one));


        /*
         * rfc 2631 2.2.1.2 (and see: handbook of applied cryptography 4.81)
         */
        do
        {
            biginteger h = bigintegers.createrandominrange(two, pminustwo, random);

            g = h.modpow(two, p);
        }
        while (g.equals(one));


        return g;
    }
}
