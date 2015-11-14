package org.ripple.bouncycastle.math.ec;

import org.ripple.bouncycastle.util.arrays;

import java.math.biginteger;

class intarray
{
    // todo make m fixed for the intarray, and hence compute t once and for all

    private int[] m_ints;

    public intarray(int intlen)
    {
        m_ints = new int[intlen];
    }

    public intarray(int[] ints)
    {
        m_ints = ints;
    }

    public intarray(biginteger bigint)
    {
        this(bigint, 0);
    }

    public intarray(biginteger bigint, int minintlen)
    {
        if (bigint.signum() == -1)
        {
            throw new illegalargumentexception("only positive integers allowed");
        }
        if (bigint.equals(ecconstants.zero))
        {
            m_ints = new int[] { 0 };
            return;
        }

        byte[] barr = bigint.tobytearray();
        int barrlen = barr.length;
        int barrstart = 0;
        if (barr[0] == 0)
        {
            // first byte is 0 to enforce highest (=sign) bit is zero.
            // in this case ignore barr[0].
            barrlen--;
            barrstart = 1;
        }
        int intlen = (barrlen + 3) / 4;
        if (intlen < minintlen)
        {
            m_ints = new int[minintlen];
        }
        else
        {
            m_ints = new int[intlen];
        }

        int iarrj = intlen - 1;
        int rem = barrlen % 4 + barrstart;
        int temp = 0;
        int barri = barrstart;
        if (barrstart < rem)
        {
            for (; barri < rem; barri++)
            {
                temp <<= 8;
                int barrbarri = barr[barri];
                if (barrbarri < 0)
                {
                    barrbarri += 256;
                }
                temp |= barrbarri;
            }
            m_ints[iarrj--] = temp;
        }

        for (; iarrj >= 0; iarrj--)
        {
            temp = 0;
            for (int i = 0; i < 4; i++)
            {
                temp <<= 8;
                int barrbarri = barr[barri++];
                if (barrbarri < 0)
                {
                    barrbarri += 256;
                }
                temp |= barrbarri;
            }
            m_ints[iarrj] = temp;
        }
    }

    public boolean iszero()
    {
        return m_ints.length == 0
            || (m_ints[0] == 0 && getusedlength() == 0);
    }

    public int getusedlength()
    {
        int highestintpos = m_ints.length;

        if (highestintpos < 1)
        {
            return 0;
        }

        // check if first element will act as sentinel
        if (m_ints[0] != 0)
        {
            while (m_ints[--highestintpos] == 0)
            {
            }
            return highestintpos + 1;
        }

        do
        {
            if (m_ints[--highestintpos] != 0)
            {
                return highestintpos + 1;
            }
        }
        while (highestintpos > 0);

        return 0;
    }

    public int bitlength()
    {
        // jdk 1.5: see integer.numberofleadingzeros()
        int intlen = getusedlength();
        if (intlen == 0)
        {
            return 0;
        }

        int last = intlen - 1;
        int highest = m_ints[last];
        int bits = (last << 5) + 1;

        // a couple of binary search steps
        if ((highest & 0xffff0000) != 0)
        {
            if ((highest & 0xff000000) != 0)
            {
                bits += 24;
                highest >>>= 24;
            }
            else
            {
                bits += 16;
                highest >>>= 16;
            }
        }
        else if (highest > 0x000000ff)
        {
            bits += 8;
            highest >>>= 8;
        }

        while (highest != 1)
        {
            ++bits;
            highest >>>= 1;
        }

        return bits;
    }

    private int[] resizedints(int newlen)
    {
        int[] newints = new int[newlen];
        int oldlen = m_ints.length;
        int copylen = oldlen < newlen ? oldlen : newlen;
        system.arraycopy(m_ints, 0, newints, 0, copylen);
        return newints;
    }

    public biginteger tobiginteger()
    {
        int usedlen = getusedlength();
        if (usedlen == 0)
        {
            return ecconstants.zero;
        }

        int highestint = m_ints[usedlen - 1];
        byte[] temp = new byte[4];
        int barri = 0;
        boolean trailingzerobytesdone = false;
        for (int j = 3; j >= 0; j--)
        {
            byte thisbyte = (byte) (highestint >>> (8 * j));
            if (trailingzerobytesdone || (thisbyte != 0))
            {
                trailingzerobytesdone = true;
                temp[barri++] = thisbyte;
            }
        }

        int barrlen = 4 * (usedlen - 1) + barri;
        byte[] barr = new byte[barrlen];
        for (int j = 0; j < barri; j++)
        {
            barr[j] = temp[j];
        }
        // highest value int is done now

        for (int iarrj = usedlen - 2; iarrj >= 0; iarrj--)
        {
            for (int j = 3; j >= 0; j--)
            {
                barr[barri++] = (byte) (m_ints[iarrj] >>> (8 * j));
            }
        }
        return new biginteger(1, barr);
    }

    public void shiftleft()
    {
        int usedlen = getusedlength();
        if (usedlen == 0)
        {
            return;
        }
        if (m_ints[usedlen - 1] < 0)
        {
            // highest bit of highest used byte is set, so shifting left will
            // make the intarray one byte longer
            usedlen++;
            if (usedlen > m_ints.length)
            {
                // make the m_ints one byte longer, because we need one more
                // byte which is not available in m_ints
                m_ints = resizedints(m_ints.length + 1);
            }
        }

        boolean carry = false;
        for (int i = 0; i < usedlen; i++)
        {
            // nextcarry is true if highest bit is set
            boolean nextcarry = m_ints[i] < 0;
            m_ints[i] <<= 1;
            if (carry)
            {
                // set lowest bit
                m_ints[i] |= 1;
            }
            carry = nextcarry;
        }
    }

    public intarray shiftleft(int n)
    {
        int usedlen = getusedlength();
        if (usedlen == 0)
        {
            return this;
        }

        if (n == 0)
        {
            return this;
        }

        if (n > 31)
        {
            throw new illegalargumentexception("shiftleft() for max 31 bits "
                + ", " + n + "bit shift is not possible");
        }

        int[] newints = new int[usedlen + 1];

        int nm32 = 32 - n;
        newints[0] = m_ints[0] << n;
        for (int i = 1; i < usedlen; i++)
        {
            newints[i] = (m_ints[i] << n) | (m_ints[i - 1] >>> nm32);
        }
        newints[usedlen] = m_ints[usedlen - 1] >>> nm32;

        return new intarray(newints);
    }

    public void addshifted(intarray other, int shift)
    {
        int usedlenother = other.getusedlength();
        int newminusedlen = usedlenother + shift;
        if (newminusedlen > m_ints.length)
        {
            m_ints = resizedints(newminusedlen);
            //system.out.println("resize required");
        }

        for (int i = 0; i < usedlenother; i++)
        {
            m_ints[i + shift] ^= other.m_ints[i];
        }
    }

    public int getlength()
    {
        return m_ints.length;
    }

    public boolean testbit(int n)
    {
        // theint = n / 32
        int theint = n >> 5;
        // thebit = n % 32
        int thebit = n & 0x1f;
        int tester = 1 << thebit;
        return ((m_ints[theint] & tester) != 0);
    }

    public void flipbit(int n)
    {
        // theint = n / 32
        int theint = n >> 5;
        // thebit = n % 32
        int thebit = n & 0x1f;
        int flipper = 1 << thebit;
        m_ints[theint] ^= flipper;
    }

    public void setbit(int n)
    {
        // theint = n / 32
        int theint = n >> 5;
        // thebit = n % 32
        int thebit = n & 0x1f;
        int setter = 1 << thebit;
        m_ints[theint] |= setter;
    }

    public intarray multiply(intarray other, int m)
    {
        // lenght of c is 2m bits rounded up to the next int (32 bit)
        int t = (m + 31) >> 5;
        if (m_ints.length < t)
        {
            m_ints = resizedints(t);
        }

        intarray b = new intarray(other.resizedints(other.getlength() + 1));
        intarray c = new intarray((m + m + 31) >> 5);
        // intarray c = new intarray(t + t);
        int testbit = 1;
        for (int k = 0; k < 32; k++)
        {
            for (int j = 0; j < t; j++)
            {
                if ((m_ints[j] & testbit) != 0)
                {
                    // the kth bit of m_ints[j] is set
                    c.addshifted(b, j);
                }
            }
            testbit <<= 1;
            b.shiftleft();
        }
        return c;
    }

    // public intarray multiplylefttoright(intarray other, int m) {
    // // lenght of c is 2m bits rounded up to the next int (32 bit)
    // int t = (m + 31) / 32;
    // if (m_ints.length < t) {
    // m_ints = resizedints(t);
    // }
    //
    // intarray b = new intarray(other.resizedints(other.getlength() + 1));
    // intarray c = new intarray((m + m + 31) / 32);
    // // intarray c = new intarray(t + t);
    // int testbit = 1 << 31;
    // for (int k = 31; k >= 0; k--) {
    // for (int j = 0; j < t; j++) {
    // if ((m_ints[j] & testbit) != 0) {
    // // the kth bit of m_ints[j] is set
    // c.addshifted(b, j);
    // }
    // }
    // testbit >>>= 1;
    // if (k > 0) {
    // c.shiftleft();
    // }
    // }
    // return c;
    // }

    // todo note, redpol.length must be 3 for tpb and 5 for ppb
    public void reduce(int m, int[] redpol)
    {
        for (int i = m + m - 2; i >= m; i--)
        {
            if (testbit(i))
            {
                int bit = i - m;
                flipbit(bit);
                flipbit(i);
                int l = redpol.length;
                while (--l >= 0)
                {
                    flipbit(redpol[l] + bit);
                }
            }
        }
        m_ints = resizedints((m + 31) >> 5);
    }

    public intarray square(int m)
    {
        // todo make the table static final
        final int[] table = { 0x0, 0x1, 0x4, 0x5, 0x10, 0x11, 0x14, 0x15, 0x40,
            0x41, 0x44, 0x45, 0x50, 0x51, 0x54, 0x55 };

        int t = (m + 31) >> 5;
        if (m_ints.length < t)
        {
            m_ints = resizedints(t);
        }

        intarray c = new intarray(t + t);

        // todo twice the same code, put in separate private method
        for (int i = 0; i < t; i++)
        {
            int v0 = 0;
            for (int j = 0; j < 4; j++)
            {
                v0 = v0 >>> 8;
                int u = (m_ints[i] >>> (j * 4)) & 0xf;
                int w = table[u] << 24;
                v0 |= w;
            }
            c.m_ints[i + i] = v0;

            v0 = 0;
            int upper = m_ints[i] >>> 16;
            for (int j = 0; j < 4; j++)
            {
                v0 = v0 >>> 8;
                int u = (upper >>> (j * 4)) & 0xf;
                int w = table[u] << 24;
                v0 |= w;
            }
            c.m_ints[i + i + 1] = v0;
        }
        return c;
    }

    public boolean equals(object o)
    {
        if (!(o instanceof intarray))
        {
            return false;
        }
        intarray other = (intarray) o;
        int usedlen = getusedlength();
        if (other.getusedlength() != usedlen)
        {
            return false;
        }
        for (int i = 0; i < usedlen; i++)
        {
            if (m_ints[i] != other.m_ints[i])
            {
                return false;
            }
        }
        return true;
    }

    public int hashcode()
    {
        int usedlen = getusedlength();
        int hash = 1;
        for (int i = 0; i < usedlen; i++)
        {
            hash = hash * 31 + m_ints[i];
        }
        return hash;
    }

    public object clone()
    {
        return new intarray(arrays.clone(m_ints));
    }

    public string tostring()
    {
        int usedlen = getusedlength();
        if (usedlen == 0)
        {
            return "0";
        }

        stringbuffer sb = new stringbuffer(integer
            .tobinarystring(m_ints[usedlen - 1]));
        for (int iarrj = usedlen - 2; iarrj >= 0; iarrj--)
        {
            string hexstring = integer.tobinarystring(m_ints[iarrj]);

            // add leading zeroes, except for highest significant int
            for (int i = hexstring.length(); i < 8; i++)
            {
                hexstring = "0" + hexstring;
            }
            sb.append(hexstring);
        }
        return sb.tostring();
    }
}
