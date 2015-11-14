package org.ripple.bouncycastle.math.ec;

import java.math.biginteger;

/**
 * class implementing the wnaf (window non-adjacent form) multiplication
 * algorithm.
 */
class wnafmultiplier implements ecmultiplier
{
    /**
     * computes the window naf (non-adjacent form) of an integer.
     * @param width the width <code>w</code> of the window naf. the width is
     * defined as the minimal number <code>w</code>, such that for any
     * <code>w</code> consecutive digits in the resulting representation, at
     * most one is non-zero.
     * @param k the integer of which the window naf is computed.
     * @return the window naf of the given width, such that the following holds:
     * <code>k = &sum;<sub>i=0</sub><sup>l-1</sup> k<sub>i</sub>2<sup>i</sup>
     * </code>, where the <code>k<sub>i</sub></code> denote the elements of the
     * returned <code>byte[]</code>.
     */
    public byte[] windownaf(byte width, biginteger k)
    {
        // the window naf is at most 1 element longer than the binary
        // representation of the integer k. byte can be used instead of short or
        // int unless the window width is larger than 8. for larger width use
        // short or int. however, a width of more than 8 is not efficient for
        // m = log2(q) smaller than 2305 bits. note: values for m larger than
        // 1000 bits are currently not used in practice.
        byte[] wnaf = new byte[k.bitlength() + 1];

        // 2^width as short and biginteger
        short pow2wb = (short)(1 << width);
        biginteger pow2wbi = biginteger.valueof(pow2wb);

        int i = 0;

        // the actual length of the wnaf
        int length = 0;

        // while k >= 1
        while (k.signum() > 0)
        {
            // if k is odd
            if (k.testbit(0))
            {
                // k mod 2^width
                biginteger remainder = k.mod(pow2wbi);

                // if remainder > 2^(width - 1) - 1
                if (remainder.testbit(width - 1))
                {
                    wnaf[i] = (byte)(remainder.intvalue() - pow2wb);
                }
                else
                {
                    wnaf[i] = (byte)remainder.intvalue();
                }
                // wnaf[i] is now in [-2^(width-1), 2^(width-1)-1]

                k = k.subtract(biginteger.valueof(wnaf[i]));
                length = i;
            }
            else
            {
                wnaf[i] = 0;
            }

            // k = k/2
            k = k.shiftright(1);
            i++;
        }

        length++;

        // reduce the wnaf array to its actual length
        byte[] wnafshort = new byte[length];
        system.arraycopy(wnaf, 0, wnafshort, 0, length);
        return wnafshort;
    }

    /**
     * multiplies <code>this</code> by an integer <code>k</code> using the
     * window naf method.
     * @param k the integer by which <code>this</code> is multiplied.
     * @return a new <code>ecpoint</code> which equals <code>this</code>
     * multiplied by <code>k</code>.
     */
    public ecpoint multiply(ecpoint p, biginteger k, precompinfo precompinfo)
    {
        wnafprecompinfo wnafprecompinfo;

        if ((precompinfo != null) && (precompinfo instanceof wnafprecompinfo))
        {
            wnafprecompinfo = (wnafprecompinfo)precompinfo;
        }
        else
        {
            // ignore empty precompinfo or precompinfo of incorrect type
            wnafprecompinfo = new wnafprecompinfo();
        }

        // floor(log2(k))
        int m = k.bitlength();

        // width of the window naf
        byte width;

        // required length of precomputation array
        int reqprecomplen;

        // determine optimal width and corresponding length of precomputation
        // array based on literature values
        if (m < 13)
        {
            width = 2;
            reqprecomplen = 1;
        }
        else
        {
            if (m < 41)
            {
                width = 3;
                reqprecomplen = 2;
            }
            else
            {
                if (m < 121)
                {
                    width = 4;
                    reqprecomplen = 4;
                }
                else
                {
                    if (m < 337)
                    {
                        width = 5;
                        reqprecomplen = 8;
                    }
                    else
                    {
                        if (m < 897)
                        {
                            width = 6;
                            reqprecomplen = 16;
                        }
                        else
                        {
                            if (m < 2305)
                            {
                                width = 7;
                                reqprecomplen = 32;
                            }
                            else
                            {
                                width = 8;
                                reqprecomplen = 127;
                            }
                        }
                    }
                }
            }
        }

        // the length of the precomputation array
        int precomplen = 1;

        ecpoint[] precomp = wnafprecompinfo.getprecomp();
        ecpoint twicep = wnafprecompinfo.gettwicep();

        // check if the precomputed ecpoints already exist
        if (precomp == null)
        {
            // precomputation must be performed from scratch, create an empty
            // precomputation array of desired length
            precomp = new ecpoint[]{ p };
        }
        else
        {
            // take the already precomputed ecpoints to start with
            precomplen = precomp.length;
        }

        if (twicep == null)
        {
            // compute twice(p)
            twicep = p.twice();
        }

        if (precomplen < reqprecomplen)
        {
            // precomputation array must be made bigger, copy existing precomp
            // array into the larger new precomp array
            ecpoint[] oldprecomp = precomp;
            precomp = new ecpoint[reqprecomplen];
            system.arraycopy(oldprecomp, 0, precomp, 0, precomplen);

            for (int i = precomplen; i < reqprecomplen; i++)
            {
                // compute the new ecpoints for the precomputation array.
                // the values 1, 3, 5, ..., 2^(width-1)-1 times p are
                // computed
                precomp[i] = twicep.add(precomp[i - 1]);
            }            
        }

        // compute the window naf of the desired width
        byte[] wnaf = windownaf(width, k);
        int l = wnaf.length;

        // apply the window naf to p using the precomputed ecpoint values.
        ecpoint q = p.getcurve().getinfinity();
        for (int i = l - 1; i >= 0; i--)
        {
            q = q.twice();

            if (wnaf[i] != 0)
            {
                if (wnaf[i] > 0)
                {
                    q = q.add(precomp[(wnaf[i] - 1)/2]);
                }
                else
                {
                    // wnaf[i] < 0
                    q = q.subtract(precomp[(-wnaf[i] - 1)/2]);
                }
            }
        }

        // set precompinfo in ecpoint, such that it is available for next
        // multiplication.
        wnafprecompinfo.setprecomp(precomp);
        wnafprecompinfo.settwicep(twicep);
        p.setprecompinfo(wnafprecompinfo);
        return q;
    }

}
