package org.ripple.bouncycastle.util;

import java.math.biginteger;
import java.security.securerandom;

/**
 * biginteger utilities.
 */
public final class bigintegers
{
    private static final int max_iterations = 1000;
    private static final biginteger zero = biginteger.valueof(0);

    /**
     * return the passed in value as an unsigned byte array.
     * 
     * @param value value to be converted.
     * @return a byte array without a leading zero byte if present in the signed encoding.
     */
    public static byte[] asunsignedbytearray(
        biginteger value)
    {
        byte[] bytes = value.tobytearray();
        
        if (bytes[0] == 0)
        {
            byte[] tmp = new byte[bytes.length - 1];
            
            system.arraycopy(bytes, 1, tmp, 0, tmp.length);
            
            return tmp;
        }
        
        return bytes;
    }

    /**
     * return the passed in value as an unsigned byte array.
     *
     * @param value value to be converted.
     * @return a byte array without a leading zero byte if present in the signed encoding.
     */
    public static byte[] asunsignedbytearray(
        int        length,
        biginteger value)
    {
        byte[] bytes = value.tobytearray();

        if (bytes[0] == 0)
        {
            if (bytes.length - 1 > length)
            {
                throw new illegalargumentexception("standard length exceeded for value");
            }

            byte[] tmp = new byte[length];

            system.arraycopy(bytes, 1, tmp, tmp.length - (bytes.length - 1), bytes.length - 1);

            return tmp;
        }
        else
        {
            if (bytes.length == length)
            {
                return bytes;
            }

            if (bytes.length > length)
            {
                throw new illegalargumentexception("standard length exceeded for value");
            }

            byte[] tmp = new byte[length];

            system.arraycopy(bytes, 0, tmp, tmp.length - bytes.length, bytes.length);

            return tmp;
        }
    }

    /**
     * return a random biginteger not less than 'min' and not greater than 'max'
     * 
     * @param min the least value that may be generated
     * @param max the greatest value that may be generated
     * @param random the source of randomness
     * @return a random biginteger value in the range [min,max]
     */
    public static biginteger createrandominrange(
        biginteger      min,
        biginteger      max,
        securerandom    random)
    {
        int cmp = min.compareto(max);
        if (cmp >= 0)
        {
            if (cmp > 0)
            {
                throw new illegalargumentexception("'min' may not be greater than 'max'");
            }

            return min;
        }

        if (min.bitlength() > max.bitlength() / 2)
        {
            return createrandominrange(zero, max.subtract(min), random).add(min);
        }

        for (int i = 0; i < max_iterations; ++i)
        {
            biginteger x = new biginteger(max.bitlength(), random);
            if (x.compareto(min) >= 0 && x.compareto(max) <= 0)
            {
                return x;
            }
        }

        // fall back to a faster (restricted) method
        return new biginteger(max.subtract(min).bitlength() - 1, random).add(min);
    }
}
