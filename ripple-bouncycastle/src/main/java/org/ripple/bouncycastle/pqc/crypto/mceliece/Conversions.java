package org.ripple.bouncycastle.pqc.crypto.mceliece;

import java.math.biginteger;

import org.ripple.bouncycastle.pqc.math.linearalgebra.bigintutils;
import org.ripple.bouncycastle.pqc.math.linearalgebra.gf2vector;
import org.ripple.bouncycastle.pqc.math.linearalgebra.integerfunctions;


/**
 * provides methods for cca2-secure conversions of mceliece pkcs
 */
final class conversions
{
    private static final biginteger zero = biginteger.valueof(0);
    private static final biginteger one = biginteger.valueof(1);
    
    /**
     * default constructor (private).
     */
    private conversions()
    {
    }

    /**
     * encode a number between 0 and (n|t) (binomial coefficient) into a binary
     * vector of length n with weight t. the number is given as a byte array.
     * only the first s bits are used, where s = floor[log(n|t)].
     *
     * @param n integer
     * @param t integer
     * @param m the message as a byte array
     * @return the encoded message as {@link gf2vector}
     */
    public static gf2vector encode(final int n, final int t, final byte[] m)
    {
        if (n < t)
        {
            throw new illegalargumentexception("n < t");
        }

        // compute the binomial c = (n|t)
        biginteger c = integerfunctions.binomial(n, t);
        // get the number encoded in m
        biginteger i = new biginteger(1, m);
        // compare
        if (i.compareto(c) >= 0)
        {
            throw new illegalargumentexception("encoded number too large.");
        }

        gf2vector result = new gf2vector(n);

        int nn = n;
        int tt = t;
        for (int j = 0; j < n; j++)
        {
            c = c.multiply(biginteger.valueof(nn - tt)).divide(
                biginteger.valueof(nn));
            nn--;
            if (c.compareto(i) <= 0)
            {
                result.setbit(j);
                i = i.subtract(c);
                tt--;
                if (nn == tt)
                {
                    c = one;
                }
                else
                {
                    c = (c.multiply(biginteger.valueof(tt + 1)))
                        .divide(biginteger.valueof(nn - tt));
                }
            }
        }

        return result;
    }

    /**
     * decode a binary vector of length n and weight t into a number between 0
     * and (n|t) (binomial coefficient). the result is given as a byte array of
     * length floor[(s+7)/8], where s = floor[log(n|t)].
     *
     * @param n   integer
     * @param t   integer
     * @param vec the binary vector
     * @return the decoded vector as a byte array
     */
    public static byte[] decode(int n, int t, gf2vector vec)
    {
        if ((vec.getlength() != n) || (vec.gethammingweight() != t))
        {
            throw new illegalargumentexception(
                "vector has wrong length or hamming weight");
        }
        int[] vecarray = vec.getvecarray();

        biginteger bc = integerfunctions.binomial(n, t);
        biginteger d = zero;
        int nn = n;
        int tt = t;
        for (int i = 0; i < n; i++)
        {
            bc = bc.multiply(biginteger.valueof(nn - tt)).divide(
                biginteger.valueof(nn));
            nn--;

            int q = i >> 5;
            int e = vecarray[q] & (1 << (i & 0x1f));
            if (e != 0)
            {
                d = d.add(bc);
                tt--;
                if (nn == tt)
                {
                    bc = one;
                }
                else
                {
                    bc = bc.multiply(biginteger.valueof(tt + 1)).divide(
                        biginteger.valueof(nn - tt));
                }

            }
        }

        return bigintutils.tominimalbytearray(d);
    }

    /**
     * compute a message representative of a message given as a vector of length
     * <tt>n</tt> bit and of hamming weight <tt>t</tt>. the result is a
     * byte array of length <tt>(s+7)/8</tt>, where
     * <tt>s = floor[log(n|t)]</tt>.
     *
     * @param n integer
     * @param t integer
     * @param m the message vector as a byte array
     * @return a message representative for <tt>m</tt>
     */
    public static byte[] signconversion(int n, int t, byte[] m)
    {
        if (n < t)
        {
            throw new illegalargumentexception("n < t");
        }

        biginteger bc = integerfunctions.binomial(n, t);
        // finds s = floor[log(binomial(n,t))]
        int s = bc.bitlength() - 1;
        // s = sq*8 + sr;
        int sq = s >> 3;
        int sr = s & 7;
        if (sr == 0)
        {
            sq--;
            sr = 8;
        }

        // n = nq*8+nr;
        int nq = n >> 3;
        int nr = n & 7;
        if (nr == 0)
        {
            nq--;
            nr = 8;
        }
        // take s bit from m
        byte[] data = new byte[nq + 1];
        if (m.length < data.length)
        {
            system.arraycopy(m, 0, data, 0, m.length);
            for (int i = m.length; i < data.length; i++)
            {
                data[i] = 0;
            }
        }
        else
        {
            system.arraycopy(m, 0, data, 0, nq);
            int h = (1 << nr) - 1;
            data[nq] = (byte)(h & m[nq]);
        }

        biginteger d = zero;
        int nn = n;
        int tt = t;
        for (int i = 0; i < n; i++)
        {
            bc = (bc.multiply(new biginteger(integer.tostring(nn - tt))))
                .divide(new biginteger(integer.tostring(nn)));
            nn--;

            int q = i >>> 3;
            int r = i & 7;
            r = 1 << r;
            byte e = (byte)(r & data[q]);
            if (e != 0)
            {
                d = d.add(bc);
                tt--;
                if (nn == tt)
                {
                    bc = one;
                }
                else
                {
                    bc = (bc
                        .multiply(new biginteger(integer.tostring(tt + 1))))
                        .divide(new biginteger(integer.tostring(nn - tt)));
                }
            }
        }

        byte[] result = new byte[sq + 1];
        byte[] help = d.tobytearray();
        if (help.length < result.length)
        {
            system.arraycopy(help, 0, result, 0, help.length);
            for (int i = help.length; i < result.length; i++)
            {
                result[i] = 0;
            }
        }
        else
        {
            system.arraycopy(help, 0, result, 0, sq);
            result[sq] = (byte)(((1 << sr) - 1) & help[sq]);
        }

        return result;
    }

}
