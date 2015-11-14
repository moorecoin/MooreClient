package org.ripple.bouncycastle.pqc.math.linearalgebra;


import java.math.biginteger;
import java.util.random;


/**
 * this class stores very long strings of bits and does some basic arithmetics.
 * it is used by <tt>gf2nfield</tt>, <tt>gf2npolynomialfield</tt> and
 * <tt>gfnpolynomialelement</tt>.
 *
 * @see gf2npolynomialelement
 * @see gf2nfield
 */
public class gf2polynomial
{

    // number of bits stored in this gf2polynomial
    private int len;

    // number of int used in value
    private int blocks;

    // storage
    private int[] value;

    // random source
    private static random rand = new random();

    // lookup-table for vectormult: parity[a]= #1(a) mod 2 == 1
    private static final boolean[] parity = {false, true, true, false, true,
        false, false, true, true, false, false, true, false, true, true,
        false, true, false, false, true, false, true, true, false, false,
        true, true, false, true, false, false, true, true, false, false,
        true, false, true, true, false, false, true, true, false, true,
        false, false, true, false, true, true, false, true, false, false,
        true, true, false, false, true, false, true, true, false, true,
        false, false, true, false, true, true, false, false, true, true,
        false, true, false, false, true, false, true, true, false, true,
        false, false, true, true, false, false, true, false, true, true,
        false, false, true, true, false, true, false, false, true, true,
        false, false, true, false, true, true, false, true, false, false,
        true, false, true, true, false, false, true, true, false, true,
        false, false, true, true, false, false, true, false, true, true,
        false, false, true, true, false, true, false, false, true, false,
        true, true, false, true, false, false, true, true, false, false,
        true, false, true, true, false, false, true, true, false, true,
        false, false, true, true, false, false, true, false, true, true,
        false, true, false, false, true, false, true, true, false, false,
        true, true, false, true, false, false, true, false, true, true,
        false, true, false, false, true, true, false, false, true, false,
        true, true, false, true, false, false, true, false, true, true,
        false, false, true, true, false, true, false, false, true, true,
        false, false, true, false, true, true, false, false, true, true,
        false, true, false, false, true, false, true, true, false, true,
        false, false, true, true, false, false, true, false, true, true,
        false};

    // lookup-table for squaring: squaringtable[a]=a^2
    private static final short[] squaringtable = {0x0000, 0x0001, 0x0004,
        0x0005, 0x0010, 0x0011, 0x0014, 0x0015, 0x0040, 0x0041, 0x0044,
        0x0045, 0x0050, 0x0051, 0x0054, 0x0055, 0x0100, 0x0101, 0x0104,
        0x0105, 0x0110, 0x0111, 0x0114, 0x0115, 0x0140, 0x0141, 0x0144,
        0x0145, 0x0150, 0x0151, 0x0154, 0x0155, 0x0400, 0x0401, 0x0404,
        0x0405, 0x0410, 0x0411, 0x0414, 0x0415, 0x0440, 0x0441, 0x0444,
        0x0445, 0x0450, 0x0451, 0x0454, 0x0455, 0x0500, 0x0501, 0x0504,
        0x0505, 0x0510, 0x0511, 0x0514, 0x0515, 0x0540, 0x0541, 0x0544,
        0x0545, 0x0550, 0x0551, 0x0554, 0x0555, 0x1000, 0x1001, 0x1004,
        0x1005, 0x1010, 0x1011, 0x1014, 0x1015, 0x1040, 0x1041, 0x1044,
        0x1045, 0x1050, 0x1051, 0x1054, 0x1055, 0x1100, 0x1101, 0x1104,
        0x1105, 0x1110, 0x1111, 0x1114, 0x1115, 0x1140, 0x1141, 0x1144,
        0x1145, 0x1150, 0x1151, 0x1154, 0x1155, 0x1400, 0x1401, 0x1404,
        0x1405, 0x1410, 0x1411, 0x1414, 0x1415, 0x1440, 0x1441, 0x1444,
        0x1445, 0x1450, 0x1451, 0x1454, 0x1455, 0x1500, 0x1501, 0x1504,
        0x1505, 0x1510, 0x1511, 0x1514, 0x1515, 0x1540, 0x1541, 0x1544,
        0x1545, 0x1550, 0x1551, 0x1554, 0x1555, 0x4000, 0x4001, 0x4004,
        0x4005, 0x4010, 0x4011, 0x4014, 0x4015, 0x4040, 0x4041, 0x4044,
        0x4045, 0x4050, 0x4051, 0x4054, 0x4055, 0x4100, 0x4101, 0x4104,
        0x4105, 0x4110, 0x4111, 0x4114, 0x4115, 0x4140, 0x4141, 0x4144,
        0x4145, 0x4150, 0x4151, 0x4154, 0x4155, 0x4400, 0x4401, 0x4404,
        0x4405, 0x4410, 0x4411, 0x4414, 0x4415, 0x4440, 0x4441, 0x4444,
        0x4445, 0x4450, 0x4451, 0x4454, 0x4455, 0x4500, 0x4501, 0x4504,
        0x4505, 0x4510, 0x4511, 0x4514, 0x4515, 0x4540, 0x4541, 0x4544,
        0x4545, 0x4550, 0x4551, 0x4554, 0x4555, 0x5000, 0x5001, 0x5004,
        0x5005, 0x5010, 0x5011, 0x5014, 0x5015, 0x5040, 0x5041, 0x5044,
        0x5045, 0x5050, 0x5051, 0x5054, 0x5055, 0x5100, 0x5101, 0x5104,
        0x5105, 0x5110, 0x5111, 0x5114, 0x5115, 0x5140, 0x5141, 0x5144,
        0x5145, 0x5150, 0x5151, 0x5154, 0x5155, 0x5400, 0x5401, 0x5404,
        0x5405, 0x5410, 0x5411, 0x5414, 0x5415, 0x5440, 0x5441, 0x5444,
        0x5445, 0x5450, 0x5451, 0x5454, 0x5455, 0x5500, 0x5501, 0x5504,
        0x5505, 0x5510, 0x5511, 0x5514, 0x5515, 0x5540, 0x5541, 0x5544,
        0x5545, 0x5550, 0x5551, 0x5554, 0x5555};

    // pre-computed bitmask for fast masking, bitmask[a]=0x1 << a
    private static final int[] bitmask = {0x00000001, 0x00000002, 0x00000004,
        0x00000008, 0x00000010, 0x00000020, 0x00000040, 0x00000080,
        0x00000100, 0x00000200, 0x00000400, 0x00000800, 0x00001000,
        0x00002000, 0x00004000, 0x00008000, 0x00010000, 0x00020000,
        0x00040000, 0x00080000, 0x00100000, 0x00200000, 0x00400000,
        0x00800000, 0x01000000, 0x02000000, 0x04000000, 0x08000000,
        0x10000000, 0x20000000, 0x40000000, 0x80000000, 0x00000000};

    // pre-computed bitmask for fast masking, rightmask[a]=0xffffffff >>> (32-a)
    private static final int[] reverserightmask = {0x00000000, 0x00000001,
        0x00000003, 0x00000007, 0x0000000f, 0x0000001f, 0x0000003f,
        0x0000007f, 0x000000ff, 0x000001ff, 0x000003ff, 0x000007ff,
        0x00000fff, 0x00001fff, 0x00003fff, 0x00007fff, 0x0000ffff,
        0x0001ffff, 0x0003ffff, 0x0007ffff, 0x000fffff, 0x001fffff,
        0x003fffff, 0x007fffff, 0x00ffffff, 0x01ffffff, 0x03ffffff,
        0x07ffffff, 0x0fffffff, 0x1fffffff, 0x3fffffff, 0x7fffffff,
        0xffffffff};

    /**
     * creates a new gf2polynomial of the given <i>length</i> and value zero.
     *
     * @param length the desired number of bits to store
     */
    public gf2polynomial(int length)
    {
        int l = length;
        if (l < 1)
        {
            l = 1;
        }
        blocks = ((l - 1) >> 5) + 1;
        value = new int[blocks];
        len = l;
    }

    /**
     * creates a new gf2polynomial of the given <i>length</i> and random value.
     *
     * @param length the desired number of bits to store
     * @param rand   securerandom to use for randomization
     */
    public gf2polynomial(int length, random rand)
    {
        int l = length;
        if (l < 1)
        {
            l = 1;
        }
        blocks = ((l - 1) >> 5) + 1;
        value = new int[blocks];
        len = l;
        randomize(rand);
    }

    /**
     * creates a new gf2polynomial of the given <i>length</i> and value
     * selected by <i>value</i>:
     * <ul>
     * <li>zero</li>
     * <li>one</li>
     * <li>random</li>
     * <li>x</li>
     * <li>all</li>
     * </ul>
     *
     * @param length the desired number of bits to store
     * @param value  the value described by a string
     */
    public gf2polynomial(int length, string value)
    {
        int l = length;
        if (l < 1)
        {
            l = 1;
        }
        blocks = ((l - 1) >> 5) + 1;
        this.value = new int[blocks];
        len = l;
        if (value.equalsignorecase("zero"))
        {
            assignzero();
        }
        else if (value.equalsignorecase("one"))
        {
            assignone();
        }
        else if (value.equalsignorecase("random"))
        {
            randomize();
        }
        else if (value.equalsignorecase("x"))
        {
            assignx();
        }
        else if (value.equalsignorecase("all"))
        {
            assignall();
        }
        else
        {
            throw new illegalargumentexception(
                "error: gf2polynomial was called using " + value
                    + " as value!");
        }

    }

    /**
     * creates a new gf2polynomial of the given <i>length</i> using the given
     * int[]. lsb is contained in bs[0].
     *
     * @param length the desired number of bits to store
     * @param bs     contains the desired value, lsb in bs[0]
     */
    public gf2polynomial(int length, int[] bs)
    {
        int leng = length;
        if (leng < 1)
        {
            leng = 1;
        }
        blocks = ((leng - 1) >> 5) + 1;
        value = new int[blocks];
        len = leng;
        int l = math.min(blocks, bs.length);
        system.arraycopy(bs, 0, value, 0, l);
        zerounusedbits();
    }

    /**
     * creates a new gf2polynomial by converting the given byte[] <i>os</i>
     * according to 1363 and using the given <i>length</i>.
     *
     * @param length the intended length of this polynomial
     * @param os     the octet string to assign to this polynomial
     * @see "p1363 5.5.2 p22f, os2bsp"
     */
    public gf2polynomial(int length, byte[] os)
    {
        int l = length;
        if (l < 1)
        {
            l = 1;
        }
        blocks = ((l - 1) >> 5) + 1;
        value = new int[blocks];
        len = l;
        int i, m;
        int k = math.min(((os.length - 1) >> 2) + 1, blocks);
        for (i = 0; i < k - 1; i++)
        {
            m = os.length - (i << 2) - 1;
            value[i] = (os[m]) & 0x000000ff;
            value[i] |= (os[m - 1] << 8) & 0x0000ff00;
            value[i] |= (os[m - 2] << 16) & 0x00ff0000;
            value[i] |= (os[m - 3] << 24) & 0xff000000;
        }
        i = k - 1;
        m = os.length - (i << 2) - 1;
        value[i] = os[m] & 0x000000ff;
        if (m > 0)
        {
            value[i] |= (os[m - 1] << 8) & 0x0000ff00;
        }
        if (m > 1)
        {
            value[i] |= (os[m - 2] << 16) & 0x00ff0000;
        }
        if (m > 2)
        {
            value[i] |= (os[m - 3] << 24) & 0xff000000;
        }
        zerounusedbits();
        reducen();
    }

    /**
     * creates a new gf2polynomial by converting the given flexibigint <i>bi</i>
     * according to 1363 and using the given <i>length</i>.
     *
     * @param length the intended length of this polynomial
     * @param bi     the flexibigint to assign to this polynomial
     * @see "p1363 5.5.1 p22, i2bsp"
     */
    public gf2polynomial(int length, biginteger bi)
    {
        int l = length;
        if (l < 1)
        {
            l = 1;
        }
        blocks = ((l - 1) >> 5) + 1;
        value = new int[blocks];
        len = l;
        int i;
        byte[] val = bi.tobytearray();
        if (val[0] == 0)
        {
            byte[] dummy = new byte[val.length - 1];
            system.arraycopy(val, 1, dummy, 0, dummy.length);
            val = dummy;
        }
        int ov = val.length & 0x03;
        int k = ((val.length - 1) >> 2) + 1;
        for (i = 0; i < ov; i++)
        {
            value[k - 1] |= (val[i] & 0x000000ff) << ((ov - 1 - i) << 3);
        }
        int m = 0;
        for (i = 0; i <= (val.length - 4) >> 2; i++)
        {
            m = val.length - 1 - (i << 2);
            value[i] = (val[m]) & 0x000000ff;
            value[i] |= ((val[m - 1]) << 8) & 0x0000ff00;
            value[i] |= ((val[m - 2]) << 16) & 0x00ff0000;
            value[i] |= ((val[m - 3]) << 24) & 0xff000000;
        }
        if ((len & 0x1f) != 0)
        {
            value[blocks - 1] &= reverserightmask[len & 0x1f];
        }
        reducen();
    }

    /**
     * creates a new gf2polynomial by cloneing the given gf2polynomial <i>b</i>.
     *
     * @param b the gf2polynomial to clone
     */
    public gf2polynomial(gf2polynomial b)
    {
        len = b.len;
        blocks = b.blocks;
        value = intutils.clone(b.value);
    }

    /**
     * @return a copy of this gf2polynomial
     */
    public object clone()
    {
        return new gf2polynomial(this);
    }

    /**
     * returns the length of this gf2polynomial. the length can be greater than
     * the degree. to get the degree call reducen() before calling getlength().
     *
     * @return the length of this gf2polynomial
     */
    public int getlength()
    {
        return len;
    }

    /**
     * returns the value of this gf2polynomial in an int[].
     *
     * @return the value of this gf2polynomial in a new int[], lsb in int[0]
     */
    public int[] tointegerarray()
    {
        int[] result;
        result = new int[blocks];
        system.arraycopy(value, 0, result, 0, blocks);
        return result;
    }

    /**
     * returns a string representing this gf2polynomials value using hexadecimal
     * or binary radix in msb-first order.
     *
     * @param radix the radix to use (2 or 16, otherwise 2 is used)
     * @return a string representing this gf2polynomials value.
     */
    public string tostring(int radix)
    {
        final char[] hex_chars = {'0', '1', '2', '3', '4', '5', '6', '7', '8',
            '9', 'a', 'b', 'c', 'd', 'e', 'f'};
        final string[] bin_chars = {"0000", "0001", "0010", "0011", "0100",
            "0101", "0110", "0111", "1000", "1001", "1010", "1011", "1100",
            "1101", "1110", "1111"};
        string res;
        int i;
        res = new string();
        if (radix == 16)
        {
            for (i = blocks - 1; i >= 0; i--)
            {
                res += hex_chars[(value[i] >>> 28) & 0x0f];
                res += hex_chars[(value[i] >>> 24) & 0x0f];
                res += hex_chars[(value[i] >>> 20) & 0x0f];
                res += hex_chars[(value[i] >>> 16) & 0x0f];
                res += hex_chars[(value[i] >>> 12) & 0x0f];
                res += hex_chars[(value[i] >>> 8) & 0x0f];
                res += hex_chars[(value[i] >>> 4) & 0x0f];
                res += hex_chars[(value[i]) & 0x0f];
                res += " ";
            }
        }
        else
        {
            for (i = blocks - 1; i >= 0; i--)
            {
                res += bin_chars[(value[i] >>> 28) & 0x0f];
                res += bin_chars[(value[i] >>> 24) & 0x0f];
                res += bin_chars[(value[i] >>> 20) & 0x0f];
                res += bin_chars[(value[i] >>> 16) & 0x0f];
                res += bin_chars[(value[i] >>> 12) & 0x0f];
                res += bin_chars[(value[i] >>> 8) & 0x0f];
                res += bin_chars[(value[i] >>> 4) & 0x0f];
                res += bin_chars[(value[i]) & 0x0f];
                res += " ";
            }
        }
        return res;
    }

    /**
     * converts this polynomial to a byte[] (octet string) according to 1363.
     *
     * @return a byte[] representing the value of this polynomial
     * @see "p1363 5.5.2 p22f, bs2osp"
     */
    public byte[] tobytearray()
    {
        int k = ((len - 1) >> 3) + 1;
        int ov = k & 0x03;
        int m;
        byte[] res = new byte[k];
        int i;
        for (i = 0; i < (k >> 2); i++)
        {
            m = k - (i << 2) - 1;
            res[m] = (byte)((value[i] & 0x000000ff));
            res[m - 1] = (byte)((value[i] & 0x0000ff00) >>> 8);
            res[m - 2] = (byte)((value[i] & 0x00ff0000) >>> 16);
            res[m - 3] = (byte)((value[i] & 0xff000000) >>> 24);
        }
        for (i = 0; i < ov; i++)
        {
            m = (ov - i - 1) << 3;
            res[i] = (byte)((value[blocks - 1] & (0x000000ff << m)) >>> m);
        }
        return res;
    }

    /**
     * converts this polynomial to an integer according to 1363.
     *
     * @return a flexibigint representing the value of this polynomial
     * @see "p1363 5.5.1 p22, bs2ip"
     */
    public biginteger toflexibigint()
    {
        if (len == 0 || iszero())
        {
            return new biginteger(0, new byte[0]);
        }
        return new biginteger(1, tobytearray());
    }

    /**
     * sets the lsb to 1 and all other to 0, assigning 'one' to this
     * gf2polynomial.
     */
    public void assignone()
    {
        int i;
        for (i = 1; i < blocks; i++)
        {
            value[i] = 0x00;
        }
        value[0] = 0x01;
    }

    /**
     * sets bit 1 to 1 and all other to 0, assigning 'x' to this gf2polynomial.
     */
    public void assignx()
    {
        int i;
        for (i = 1; i < blocks; i++)
        {
            value[i] = 0x00;
        }
        value[0] = 0x02;
    }

    /**
     * sets all bits to 1.
     */
    public void assignall()
    {
        int i;
        for (i = 0; i < blocks; i++)
        {
            value[i] = 0xffffffff;
        }
        zerounusedbits();
    }

    /**
     * resets all bits to zero.
     */
    public void assignzero()
    {
        int i;
        for (i = 0; i < blocks; i++)
        {
            value[i] = 0x00;
        }
    }

    /**
     * fills all len bits of this gf2polynomial with random values.
     */
    public void randomize()
    {
        int i;
        for (i = 0; i < blocks; i++)
        {
            value[i] = rand.nextint();
        }
        zerounusedbits();
    }

    /**
     * fills all len bits of this gf2polynomial with random values using the
     * specified source of randomness.
     *
     * @param rand the source of randomness
     */
    public void randomize(random rand)
    {
        int i;
        for (i = 0; i < blocks; i++)
        {
            value[i] = rand.nextint();
        }
        zerounusedbits();
    }

    /**
     * returns true if two gf2polynomials have the same size and value and thus
     * are equal.
     *
     * @param other the other gf2polynomial
     * @return true if this gf2polynomial equals <i>b</i> (<i>this</i> ==
     *         <i>b</i>)
     */
    public boolean equals(object other)
    {
        if (other == null || !(other instanceof gf2polynomial))
        {
            return false;
        }

        gf2polynomial otherpol = (gf2polynomial)other;

        if (len != otherpol.len)
        {
            return false;
        }
        for (int i = 0; i < blocks; i++)
        {
            if (value[i] != otherpol.value[i])
            {
                return false;
            }
        }
        return true;
    }

    /**
     * @return the hash code of this polynomial
     */
    public int hashcode()
    {
        return len + value.hashcode();
    }

    /**
     * tests if all bits equal zero.
     *
     * @return true if this gf2polynomial equals 'zero' (<i>this</i> == 0)
     */
    public boolean iszero()
    {
        int i;
        if (len == 0)
        {
            return true;
        }
        for (i = 0; i < blocks; i++)
        {
            if (value[i] != 0)
            {
                return false;
            }
        }
        return true;
    }

    /**
     * tests if all bits are reset to 0 and lsb is set to 1.
     *
     * @return true if this gf2polynomial equals 'one' (<i>this</i> == 1)
     */
    public boolean isone()
    {
        int i;
        for (i = 1; i < blocks; i++)
        {
            if (value[i] != 0)
            {
                return false;
            }
        }
        if (value[0] != 0x01)
        {
            return false;
        }
        return true;
    }

    /**
     * adds <i>b</i> to this gf2polynomial and assigns the result to this
     * gf2polynomial. <i>b</i> can be of different size.
     *
     * @param b gf2polynomial to add to this gf2polynomial
     */
    public void addtothis(gf2polynomial b)
    {
        expandn(b.len);
        xorthisby(b);
    }

    /**
     * adds two gf2polynomials, <i>this</i> and <i>b</i>, and returns the
     * result. <i>this</i> and <i>b</i> can be of different size.
     *
     * @param b a gf2polynomial
     * @return a new gf2polynomial (<i>this</i> + <i>b</i>)
     */
    public gf2polynomial add(gf2polynomial b)
    {
        return xor(b);
    }

    /**
     * subtracts <i>b</i> from this gf2polynomial and assigns the result to
     * this gf2polynomial. <i>b</i> can be of different size.
     *
     * @param b a gf2polynomial
     */
    public void subtractfromthis(gf2polynomial b)
    {
        expandn(b.len);
        xorthisby(b);
    }

    /**
     * subtracts two gf2polynomials, <i>this</i> and <i>b</i>, and returns the
     * result in a new gf2polynomial. <i>this</i> and <i>b</i> can be of
     * different size.
     *
     * @param b a gf2polynomial
     * @return a new gf2polynomial (<i>this</i> - <i>b</i>)
     */
    public gf2polynomial subtract(gf2polynomial b)
    {
        return xor(b);
    }

    /**
     * toggles the lsb of this gf2polynomial, increasing its value by 'one'.
     */
    public void increasethis()
    {
        xorbit(0);
    }

    /**
     * toggles the lsb of this gf2polynomial, increasing the value by 'one' and
     * returns the result in a new gf2polynomial.
     *
     * @return <tt>this + 1</tt>
     */
    public gf2polynomial increase()
    {
        gf2polynomial result = new gf2polynomial(this);
        result.increasethis();
        return result;
    }

    /**
     * multiplies this gf2polynomial with <i>b</i> and returns the result in a
     * new gf2polynomial. this method does not reduce the result in gf(2^n).
     * this method uses classic multiplication (schoolbook).
     *
     * @param b a gf2polynomial
     * @return a new gf2polynomial (<i>this</i> * <i>b</i>)
     */
    public gf2polynomial multiplyclassic(gf2polynomial b)
    {
        gf2polynomial result = new gf2polynomial(math.max(len, b.len) << 1);
        gf2polynomial[] m = new gf2polynomial[32];
        int i, j;
        m[0] = new gf2polynomial(this);
        for (i = 1; i <= 31; i++)
        {
            m[i] = m[i - 1].shiftleft();
        }
        for (i = 0; i < b.blocks; i++)
        {
            for (j = 0; j <= 31; j++)
            {
                if ((b.value[i] & bitmask[j]) != 0)
                {
                    result.xorthisby(m[j]);
                }
            }
            for (j = 0; j <= 31; j++)
            {
                m[j].shiftblocksleft();
            }
        }
        return result;
    }

    /**
     * multiplies this gf2polynomial with <i>b</i> and returns the result in a
     * new gf2polynomial. this method does not reduce the result in gf(2^n).
     * this method uses karatzuba multiplication.
     *
     * @param b a gf2polynomial
     * @return a new gf2polynomial (<i>this</i> * <i>b</i>)
     */
    public gf2polynomial multiply(gf2polynomial b)
    {
        int n = math.max(len, b.len);
        expandn(n);
        b.expandn(n);
        return karamult(b);
    }

    /**
     * does the recursion for karatzuba multiplication.
     */
    private gf2polynomial karamult(gf2polynomial b)
    {
        gf2polynomial result = new gf2polynomial(len << 1);
        if (len <= 32)
        {
            result.value = mult32(value[0], b.value[0]);
            return result;
        }
        if (len <= 64)
        {
            result.value = mult64(value, b.value);
            return result;
        }
        if (len <= 128)
        {
            result.value = mult128(value, b.value);
            return result;
        }
        if (len <= 256)
        {
            result.value = mult256(value, b.value);
            return result;
        }
        if (len <= 512)
        {
            result.value = mult512(value, b.value);
            return result;
        }

        int n = integerfunctions.floorlog(len - 1);
        n = bitmask[n];

        gf2polynomial a0 = lower(((n - 1) >> 5) + 1);
        gf2polynomial a1 = upper(((n - 1) >> 5) + 1);
        gf2polynomial b0 = b.lower(((n - 1) >> 5) + 1);
        gf2polynomial b1 = b.upper(((n - 1) >> 5) + 1);

        gf2polynomial c = a1.karamult(b1); // c = a1*b1
        gf2polynomial e = a0.karamult(b0); // e = a0*b0
        a0.addtothis(a1); // a0 = a0 + a1
        b0.addtothis(b1); // b0 = b0 + b1
        gf2polynomial d = a0.karamult(b0); // d = (a0+a1)*(b0+b1)

        result.shiftleftaddthis(c, n << 1);
        result.shiftleftaddthis(c, n);
        result.shiftleftaddthis(d, n);
        result.shiftleftaddthis(e, n);
        result.addtothis(e);
        return result;
    }

    /**
     * 16-integer version of karatzuba multiplication.
     */
    private static int[] mult512(int[] a, int[] b)
    {
        int[] result = new int[32];
        int[] a0 = new int[8];
        system.arraycopy(a, 0, a0, 0, math.min(8, a.length));
        int[] a1 = new int[8];
        if (a.length > 8)
        {
            system.arraycopy(a, 8, a1, 0, math.min(8, a.length - 8));
        }
        int[] b0 = new int[8];
        system.arraycopy(b, 0, b0, 0, math.min(8, b.length));
        int[] b1 = new int[8];
        if (b.length > 8)
        {
            system.arraycopy(b, 8, b1, 0, math.min(8, b.length - 8));
        }
        int[] c = mult256(a1, b1);
        result[31] ^= c[15];
        result[30] ^= c[14];
        result[29] ^= c[13];
        result[28] ^= c[12];
        result[27] ^= c[11];
        result[26] ^= c[10];
        result[25] ^= c[9];
        result[24] ^= c[8];
        result[23] ^= c[7] ^ c[15];
        result[22] ^= c[6] ^ c[14];
        result[21] ^= c[5] ^ c[13];
        result[20] ^= c[4] ^ c[12];
        result[19] ^= c[3] ^ c[11];
        result[18] ^= c[2] ^ c[10];
        result[17] ^= c[1] ^ c[9];
        result[16] ^= c[0] ^ c[8];
        result[15] ^= c[7];
        result[14] ^= c[6];
        result[13] ^= c[5];
        result[12] ^= c[4];
        result[11] ^= c[3];
        result[10] ^= c[2];
        result[9] ^= c[1];
        result[8] ^= c[0];
        a1[0] ^= a0[0];
        a1[1] ^= a0[1];
        a1[2] ^= a0[2];
        a1[3] ^= a0[3];
        a1[4] ^= a0[4];
        a1[5] ^= a0[5];
        a1[6] ^= a0[6];
        a1[7] ^= a0[7];
        b1[0] ^= b0[0];
        b1[1] ^= b0[1];
        b1[2] ^= b0[2];
        b1[3] ^= b0[3];
        b1[4] ^= b0[4];
        b1[5] ^= b0[5];
        b1[6] ^= b0[6];
        b1[7] ^= b0[7];
        int[] d = mult256(a1, b1);
        result[23] ^= d[15];
        result[22] ^= d[14];
        result[21] ^= d[13];
        result[20] ^= d[12];
        result[19] ^= d[11];
        result[18] ^= d[10];
        result[17] ^= d[9];
        result[16] ^= d[8];
        result[15] ^= d[7];
        result[14] ^= d[6];
        result[13] ^= d[5];
        result[12] ^= d[4];
        result[11] ^= d[3];
        result[10] ^= d[2];
        result[9] ^= d[1];
        result[8] ^= d[0];
        int[] e = mult256(a0, b0);
        result[23] ^= e[15];
        result[22] ^= e[14];
        result[21] ^= e[13];
        result[20] ^= e[12];
        result[19] ^= e[11];
        result[18] ^= e[10];
        result[17] ^= e[9];
        result[16] ^= e[8];
        result[15] ^= e[7] ^ e[15];
        result[14] ^= e[6] ^ e[14];
        result[13] ^= e[5] ^ e[13];
        result[12] ^= e[4] ^ e[12];
        result[11] ^= e[3] ^ e[11];
        result[10] ^= e[2] ^ e[10];
        result[9] ^= e[1] ^ e[9];
        result[8] ^= e[0] ^ e[8];
        result[7] ^= e[7];
        result[6] ^= e[6];
        result[5] ^= e[5];
        result[4] ^= e[4];
        result[3] ^= e[3];
        result[2] ^= e[2];
        result[1] ^= e[1];
        result[0] ^= e[0];
        return result;
    }

    /**
     * 8-integer version of karatzuba multiplication.
     */
    private static int[] mult256(int[] a, int[] b)
    {
        int[] result = new int[16];
        int[] a0 = new int[4];
        system.arraycopy(a, 0, a0, 0, math.min(4, a.length));
        int[] a1 = new int[4];
        if (a.length > 4)
        {
            system.arraycopy(a, 4, a1, 0, math.min(4, a.length - 4));
        }
        int[] b0 = new int[4];
        system.arraycopy(b, 0, b0, 0, math.min(4, b.length));
        int[] b1 = new int[4];
        if (b.length > 4)
        {
            system.arraycopy(b, 4, b1, 0, math.min(4, b.length - 4));
        }
        if (a1[3] == 0 && a1[2] == 0 && b1[3] == 0 && b1[2] == 0)
        {
            if (a1[1] == 0 && b1[1] == 0)
            {
                if (a1[0] != 0 || b1[0] != 0)
                { // [3]=[2]=[1]=0, [0]!=0
                    int[] c = mult32(a1[0], b1[0]);
                    result[9] ^= c[1];
                    result[8] ^= c[0];
                    result[5] ^= c[1];
                    result[4] ^= c[0];
                }
            }
            else
            { // [3]=[2]=0 [1]!=0, [0]!=0
                int[] c = mult64(a1, b1);
                result[11] ^= c[3];
                result[10] ^= c[2];
                result[9] ^= c[1];
                result[8] ^= c[0];
                result[7] ^= c[3];
                result[6] ^= c[2];
                result[5] ^= c[1];
                result[4] ^= c[0];
            }
        }
        else
        { // [3]!=0 [2]!=0 [1]!=0, [0]!=0
            int[] c = mult128(a1, b1);
            result[15] ^= c[7];
            result[14] ^= c[6];
            result[13] ^= c[5];
            result[12] ^= c[4];
            result[11] ^= c[3] ^ c[7];
            result[10] ^= c[2] ^ c[6];
            result[9] ^= c[1] ^ c[5];
            result[8] ^= c[0] ^ c[4];
            result[7] ^= c[3];
            result[6] ^= c[2];
            result[5] ^= c[1];
            result[4] ^= c[0];
        }
        a1[0] ^= a0[0];
        a1[1] ^= a0[1];
        a1[2] ^= a0[2];
        a1[3] ^= a0[3];
        b1[0] ^= b0[0];
        b1[1] ^= b0[1];
        b1[2] ^= b0[2];
        b1[3] ^= b0[3];
        int[] d = mult128(a1, b1);
        result[11] ^= d[7];
        result[10] ^= d[6];
        result[9] ^= d[5];
        result[8] ^= d[4];
        result[7] ^= d[3];
        result[6] ^= d[2];
        result[5] ^= d[1];
        result[4] ^= d[0];
        int[] e = mult128(a0, b0);
        result[11] ^= e[7];
        result[10] ^= e[6];
        result[9] ^= e[5];
        result[8] ^= e[4];
        result[7] ^= e[3] ^ e[7];
        result[6] ^= e[2] ^ e[6];
        result[5] ^= e[1] ^ e[5];
        result[4] ^= e[0] ^ e[4];
        result[3] ^= e[3];
        result[2] ^= e[2];
        result[1] ^= e[1];
        result[0] ^= e[0];
        return result;
    }

    /**
     * 4-integer version of karatzuba multiplication.
     */
    private static int[] mult128(int[] a, int[] b)
    {
        int[] result = new int[8];
        int[] a0 = new int[2];
        system.arraycopy(a, 0, a0, 0, math.min(2, a.length));
        int[] a1 = new int[2];
        if (a.length > 2)
        {
            system.arraycopy(a, 2, a1, 0, math.min(2, a.length - 2));
        }
        int[] b0 = new int[2];
        system.arraycopy(b, 0, b0, 0, math.min(2, b.length));
        int[] b1 = new int[2];
        if (b.length > 2)
        {
            system.arraycopy(b, 2, b1, 0, math.min(2, b.length - 2));
        }
        if (a1[1] == 0 && b1[1] == 0)
        {
            if (a1[0] != 0 || b1[0] != 0)
            {
                int[] c = mult32(a1[0], b1[0]);
                result[5] ^= c[1];
                result[4] ^= c[0];
                result[3] ^= c[1];
                result[2] ^= c[0];
            }
        }
        else
        {
            int[] c = mult64(a1, b1);
            result[7] ^= c[3];
            result[6] ^= c[2];
            result[5] ^= c[1] ^ c[3];
            result[4] ^= c[0] ^ c[2];
            result[3] ^= c[1];
            result[2] ^= c[0];
        }
        a1[0] ^= a0[0];
        a1[1] ^= a0[1];
        b1[0] ^= b0[0];
        b1[1] ^= b0[1];
        if (a1[1] == 0 && b1[1] == 0)
        {
            int[] d = mult32(a1[0], b1[0]);
            result[3] ^= d[1];
            result[2] ^= d[0];
        }
        else
        {
            int[] d = mult64(a1, b1);
            result[5] ^= d[3];
            result[4] ^= d[2];
            result[3] ^= d[1];
            result[2] ^= d[0];
        }
        if (a0[1] == 0 && b0[1] == 0)
        {
            int[] e = mult32(a0[0], b0[0]);
            result[3] ^= e[1];
            result[2] ^= e[0];
            result[1] ^= e[1];
            result[0] ^= e[0];
        }
        else
        {
            int[] e = mult64(a0, b0);
            result[5] ^= e[3];
            result[4] ^= e[2];
            result[3] ^= e[1] ^ e[3];
            result[2] ^= e[0] ^ e[2];
            result[1] ^= e[1];
            result[0] ^= e[0];
        }
        return result;
    }

    /**
     * 2-integer version of karatzuba multiplication.
     */
    private static int[] mult64(int[] a, int[] b)
    {
        int[] result = new int[4];
        int a0 = a[0];
        int a1 = 0;
        if (a.length > 1)
        {
            a1 = a[1];
        }
        int b0 = b[0];
        int b1 = 0;
        if (b.length > 1)
        {
            b1 = b[1];
        }
        if (a1 != 0 || b1 != 0)
        {
            int[] c = mult32(a1, b1);
            result[3] ^= c[1];
            result[2] ^= c[0] ^ c[1];
            result[1] ^= c[0];
        }
        int[] d = mult32(a0 ^ a1, b0 ^ b1);
        result[2] ^= d[1];
        result[1] ^= d[0];
        int[] e = mult32(a0, b0);
        result[2] ^= e[1];
        result[1] ^= e[0] ^ e[1];
        result[0] ^= e[0];
        return result;
    }

    /**
     * 4-byte version of karatzuba multiplication. here the actual work is done.
     */
    private static int[] mult32(int a, int b)
    {
        int[] result = new int[2];
        if (a == 0 || b == 0)
        {
            return result;
        }
        long b2 = b;
        b2 &= 0x00000000ffffffffl;
        int i;
        long h = 0;
        for (i = 1; i <= 32; i++)
        {
            if ((a & bitmask[i - 1]) != 0)
            {
                h ^= b2;
            }
            b2 <<= 1;
        }
        result[1] = (int)(h >>> 32);
        result[0] = (int)(h & 0x00000000ffffffffl);
        return result;
    }

    /**
     * returns a new gf2polynomial containing the upper <i>k</i> bytes of this
     * gf2polynomial.
     *
     * @param k
     * @return a new gf2polynomial containing the upper <i>k</i> bytes of this
     *         gf2polynomial
     * @see gf2polynomial#karamult
     */
    private gf2polynomial upper(int k)
    {
        int j = math.min(k, blocks - k);
        gf2polynomial result = new gf2polynomial(j << 5);
        if (blocks >= k)
        {
            system.arraycopy(value, k, result.value, 0, j);
        }
        return result;
    }

    /**
     * returns a new gf2polynomial containing the lower <i>k</i> bytes of this
     * gf2polynomial.
     *
     * @param k
     * @return a new gf2polynomial containing the lower <i>k</i> bytes of this
     *         gf2polynomial
     * @see gf2polynomial#karamult
     */
    private gf2polynomial lower(int k)
    {
        gf2polynomial result = new gf2polynomial(k << 5);
        system.arraycopy(value, 0, result.value, 0, math.min(k, blocks));
        return result;
    }

    /**
     * returns the remainder of <i>this</i> divided by <i>g</i> in a new
     * gf2polynomial.
     *
     * @param g gf2polynomial != 0
     * @return a new gf2polynomial (<i>this</i> % <i>g</i>)
     * @throws polynomialiszeroexception if <i>g</i> equals zero
     */
    public gf2polynomial remainder(gf2polynomial g)
        throws runtimeexception
    {
        /* a div b = q / r */
        gf2polynomial a = new gf2polynomial(this);
        gf2polynomial b = new gf2polynomial(g);
        gf2polynomial j;
        int i;
        if (b.iszero())
        {
            throw new runtimeexception();
        }
        a.reducen();
        b.reducen();
        if (a.len < b.len)
        {
            return a;
        }
        i = a.len - b.len;
        while (i >= 0)
        {
            j = b.shiftleft(i);
            a.subtractfromthis(j);
            a.reducen();
            i = a.len - b.len;
        }
        return a;
    }

    /**
     * returns the absolute quotient of <i>this</i> divided by <i>g</i> in a
     * new gf2polynomial.
     *
     * @param g gf2polynomial != 0
     * @return a new gf2polynomial |_ <i>this</i> / <i>g</i> _|
     * @throws polynomialiszeroexception if <i>g</i> equals zero
     */
    public gf2polynomial quotient(gf2polynomial g)
        throws runtimeexception
    {
        /* a div b = q / r */
        gf2polynomial q = new gf2polynomial(len);
        gf2polynomial a = new gf2polynomial(this);
        gf2polynomial b = new gf2polynomial(g);
        gf2polynomial j;
        int i;
        if (b.iszero())
        {
            throw new runtimeexception();
        }
        a.reducen();
        b.reducen();
        if (a.len < b.len)
        {
            return new gf2polynomial(0);
        }
        i = a.len - b.len;
        q.expandn(i + 1);

        while (i >= 0)
        {
            j = b.shiftleft(i);
            a.subtractfromthis(j);
            a.reducen();
            q.xorbit(i);
            i = a.len - b.len;
        }

        return q;
    }

    /**
     * divides <i>this</i> by <i>g</i> and returns the quotient and remainder
     * in a new gf2polynomial[2], quotient in [0], remainder in [1].
     *
     * @param g gf2polynomial != 0
     * @return a new gf2polynomial[2] containing quotient and remainder
     * @throws polynomialiszeroexception if <i>g</i> equals zero
     */
    public gf2polynomial[] divide(gf2polynomial g)
        throws runtimeexception
    {
        /* a div b = q / r */
        gf2polynomial[] result = new gf2polynomial[2];
        gf2polynomial q = new gf2polynomial(len);
        gf2polynomial a = new gf2polynomial(this);
        gf2polynomial b = new gf2polynomial(g);
        gf2polynomial j;
        int i;
        if (b.iszero())
        {
            throw new runtimeexception();
        }
        a.reducen();
        b.reducen();
        if (a.len < b.len)
        {
            result[0] = new gf2polynomial(0);
            result[1] = a;
            return result;
        }
        i = a.len - b.len;
        q.expandn(i + 1);

        while (i >= 0)
        {
            j = b.shiftleft(i);
            a.subtractfromthis(j);
            a.reducen();
            q.xorbit(i);
            i = a.len - b.len;
        }

        result[0] = q;
        result[1] = a;
        return result;
    }

    /**
     * returns the greatest common divisor of <i>this</i> and <i>g</i> in a
     * new gf2polynomial.
     *
     * @param g gf2polynomial != 0
     * @return a new gf2polynomial gcd(<i>this</i>,<i>g</i>)
     * @throws arithmeticexception if <i>this</i> and <i>g</i> both are equal to zero
     * @throws polynomialiszeroexception to be api-compliant (should never be thrown).
     */
    public gf2polynomial gcd(gf2polynomial g)
        throws runtimeexception
    {
        if (iszero() && g.iszero())
        {
            throw new arithmeticexception("both operands of gcd equal zero.");
        }
        if (iszero())
        {
            return new gf2polynomial(g);
        }
        if (g.iszero())
        {
            return new gf2polynomial(this);
        }
        gf2polynomial a = new gf2polynomial(this);
        gf2polynomial b = new gf2polynomial(g);
        gf2polynomial c;

        while (!b.iszero())
        {
            c = a.remainder(b);
            a = b;
            b = c;
        }

        return a;
    }

    /**
     * checks if <i>this</i> is irreducible, according to ieee p1363, a.5.5,
     * p103. <br />
     * note: the algorithm from ieee p1363, a5.5 can be used to check a
     * polynomial with coefficients in gf(2^r) for irreducibility. as this class
     * only represents polynomials with coefficients in gf(2), the algorithm is
     * adapted to the case r=1.
     *
     * @return true if <i>this</i> is irreducible
     * @see "p1363, a.5.5, p103"
     */
    public boolean isirreducible()
    {
        if (iszero())
        {
            return false;
        }
        gf2polynomial f = new gf2polynomial(this);
        int d, i;
        gf2polynomial u, g;
        gf2polynomial dummy;
        f.reducen();
        d = f.len - 1;
        u = new gf2polynomial(f.len, "x");

        for (i = 1; i <= (d >> 1); i++)
        {
            u.squarethisprecalc();
            u = u.remainder(f);
            dummy = u.add(new gf2polynomial(32, "x"));
            if (!dummy.iszero())
            {
                g = f.gcd(dummy);
                if (!g.isone())
                {
                    return false;
                }
            }
            else
            {
                return false;
            }
        }

        return true;
    }

    /**
     * reduces this gf2polynomial using the trinomial x^<i>m</i> + x^<i>tc</i> +
     * 1.
     *
     * @param m  the degree of the used field
     * @param tc degree of the middle x in the trinomial
     */
    void reducetrinomial(int m, int tc)
    {
        int i;
        int p0, p1;
        int q0, q1;
        long t;
        p0 = m >>> 5; // block which contains 2^m
        q0 = 32 - (m & 0x1f); // (32-index) of 2^m within block p0
        p1 = (m - tc) >>> 5; // block which contains 2^tc
        q1 = 32 - ((m - tc) & 0x1f); // (32-index) of 2^tc within block q1
        int max = ((m << 1) - 2) >>> 5; // block which contains 2^(2m-2)
        int min = p0; // block which contains 2^m
        for (i = max; i > min; i--)
        { // for i = maxblock to minblock
            // reduce coefficients contained in t
            // t = block[i]
            t = value[i] & 0x00000000ffffffffl;
            // block[i-p0-1] ^= t << q0
            value[i - p0 - 1] ^= (int)(t << q0);
            // block[i-p0] ^= t >>> (32-q0)
            value[i - p0] ^= t >>> (32 - q0);
            // block[i-p1-1] ^= << q1
            value[i - p1 - 1] ^= (int)(t << q1);
            // block[i-p1] ^= t >>> (32-q1)
            value[i - p1] ^= t >>> (32 - q1);
            value[i] = 0x00;
        }
        // reduce last coefficients in block containing 2^m
        t = value[min] & 0x00000000ffffffffl & (0xffffffffl << (m & 0x1f)); // t
        // contains the last coefficients > m
        value[0] ^= t >>> (32 - q0);
        if (min - p1 - 1 >= 0)
        {
            value[min - p1 - 1] ^= (int)(t << q1);
        }
        value[min - p1] ^= t >>> (32 - q1);

        value[min] &= reverserightmask[m & 0x1f];
        blocks = ((m - 1) >>> 5) + 1;
        len = m;
    }

    /**
     * reduces this gf2polynomial using the pentanomial x^<i>m</i> + x^<i>pc[2]</i> +
     * x^<i>pc[1]</i> + x^<i>pc[0]</i> + 1.
     *
     * @param m  the degree of the used field
     * @param pc degrees of the middle x's in the pentanomial
     */
    void reducepentanomial(int m, int[] pc)
    {
        int i;
        int p0, p1, p2, p3;
        int q0, q1, q2, q3;
        long t;
        p0 = m >>> 5;
        q0 = 32 - (m & 0x1f);
        p1 = (m - pc[0]) >>> 5;
        q1 = 32 - ((m - pc[0]) & 0x1f);
        p2 = (m - pc[1]) >>> 5;
        q2 = 32 - ((m - pc[1]) & 0x1f);
        p3 = (m - pc[2]) >>> 5;
        q3 = 32 - ((m - pc[2]) & 0x1f);
        int max = ((m << 1) - 2) >>> 5;
        int min = p0;
        for (i = max; i > min; i--)
        {
            t = value[i] & 0x00000000ffffffffl;
            value[i - p0 - 1] ^= (int)(t << q0);
            value[i - p0] ^= t >>> (32 - q0);
            value[i - p1 - 1] ^= (int)(t << q1);
            value[i - p1] ^= t >>> (32 - q1);
            value[i - p2 - 1] ^= (int)(t << q2);
            value[i - p2] ^= t >>> (32 - q2);
            value[i - p3 - 1] ^= (int)(t << q3);
            value[i - p3] ^= t >>> (32 - q3);
            value[i] = 0;
        }
        t = value[min] & 0x00000000ffffffffl & (0xffffffffl << (m & 0x1f));
        value[0] ^= t >>> (32 - q0);
        if (min - p1 - 1 >= 0)
        {
            value[min - p1 - 1] ^= (int)(t << q1);
        }
        value[min - p1] ^= t >>> (32 - q1);
        if (min - p2 - 1 >= 0)
        {
            value[min - p2 - 1] ^= (int)(t << q2);
        }
        value[min - p2] ^= t >>> (32 - q2);
        if (min - p3 - 1 >= 0)
        {
            value[min - p3 - 1] ^= (int)(t << q3);
        }
        value[min - p3] ^= t >>> (32 - q3);
        value[min] &= reverserightmask[m & 0x1f];

        blocks = ((m - 1) >>> 5) + 1;
        len = m;
    }

    /**
     * reduces len by finding the most significant bit set to one and reducing
     * len and blocks.
     */
    public void reducen()
    {
        int i, j, h;
        i = blocks - 1;
        while ((value[i] == 0) && (i > 0))
        {
            i--;
        }
        h = value[i];
        j = 0;
        while (h != 0)
        {
            h >>>= 1;
            j++;
        }
        len = (i << 5) + j;
        blocks = i + 1;
    }

    /**
     * expands len and int[] value to <i>i</i>. this is useful before adding
     * two gf2polynomials of different size.
     *
     * @param i the intended length
     */
    public void expandn(int i)
    {
        int k;
        int[] bs;
        if (len >= i)
        {
            return;
        }
        len = i;
        k = ((i - 1) >>> 5) + 1;
        if (blocks >= k)
        {
            return;
        }
        if (value.length >= k)
        {
            int j;
            for (j = blocks; j < k; j++)
            {
                value[j] = 0;
            }
            blocks = k;
            return;
        }
        bs = new int[k];
        system.arraycopy(value, 0, bs, 0, blocks);
        blocks = k;
        value = null;
        value = bs;
    }

    /**
     * squares this gf2polynomial and expands it accordingly. this method does
     * not reduce the result in gf(2^n). there exists a faster method for
     * squaring in gf(2^n).
     *
     * @see gf2npolynomialelement#square
     */
    public void squarethisbitwise()
    {
        int i, h, j, k;
        if (iszero())
        {
            return;
        }
        int[] result = new int[blocks << 1];
        for (i = blocks - 1; i >= 0; i--)
        {
            h = value[i];
            j = 0x00000001;
            for (k = 0; k < 16; k++)
            {
                if ((h & 0x01) != 0)
                {
                    result[i << 1] |= j;
                }
                if ((h & 0x00010000) != 0)
                {
                    result[(i << 1) + 1] |= j;
                }
                j <<= 2;
                h >>>= 1;
            }
        }
        value = null;
        value = result;
        blocks = result.length;
        len = (len << 1) - 1;
    }

    /**
     * squares this gf2polynomial by using precomputed values of squaringtable.
     * this method does not reduce the result in gf(2^n).
     */
    public void squarethisprecalc()
    {
        int i;
        if (iszero())
        {
            return;
        }
        if (value.length >= (blocks << 1))
        {
            for (i = blocks - 1; i >= 0; i--)
            {
                value[(i << 1) + 1] = gf2polynomial.squaringtable[(value[i] & 0x00ff0000) >>> 16]
                    | (gf2polynomial.squaringtable[(value[i] & 0xff000000) >>> 24] << 16);
                value[i << 1] = gf2polynomial.squaringtable[value[i] & 0x000000ff]
                    | (gf2polynomial.squaringtable[(value[i] & 0x0000ff00) >>> 8] << 16);
            }
            blocks <<= 1;
            len = (len << 1) - 1;
        }
        else
        {
            int[] result = new int[blocks << 1];
            for (i = 0; i < blocks; i++)
            {
                result[i << 1] = gf2polynomial.squaringtable[value[i] & 0x000000ff]
                    | (gf2polynomial.squaringtable[(value[i] & 0x0000ff00) >>> 8] << 16);
                result[(i << 1) + 1] = gf2polynomial.squaringtable[(value[i] & 0x00ff0000) >>> 16]
                    | (gf2polynomial.squaringtable[(value[i] & 0xff000000) >>> 24] << 16);
            }
            value = null;
            value = result;
            blocks <<= 1;
            len = (len << 1) - 1;
        }
    }

    /**
     * does a vector-multiplication modulo 2 and returns the result as boolean.
     *
     * @param b gf2polynomial
     * @return this x <i>b</i> as boolean (1->true, 0->false)
     * @throws polynomialshavedifferentlengthexception if <i>this</i> and <i>b</i> have a different length and
     * thus cannot be vector-multiplied
     */
    public boolean vectormult(gf2polynomial b)
        throws runtimeexception
    {
        int i;
        int h;
        boolean result = false;
        if (len != b.len)
        {
            throw new runtimeexception();
        }
        for (i = 0; i < blocks; i++)
        {
            h = value[i] & b.value[i];
            result ^= parity[h & 0x000000ff];
            result ^= parity[(h >>> 8) & 0x000000ff];
            result ^= parity[(h >>> 16) & 0x000000ff];
            result ^= parity[(h >>> 24) & 0x000000ff];
        }
        return result;
    }

    /**
     * returns the bitwise exclusive-or of <i>this</i> and <i>b</i> in a new
     * gf2polynomial. <i>this</i> and <i>b</i> can be of different size.
     *
     * @param b gf2polynomial
     * @return a new gf2polynomial (<i>this</i> ^ <i>b</i>)
     */
    public gf2polynomial xor(gf2polynomial b)
    {
        int i;
        gf2polynomial result;
        int k = math.min(blocks, b.blocks);
        if (len >= b.len)
        {
            result = new gf2polynomial(this);
            for (i = 0; i < k; i++)
            {
                result.value[i] ^= b.value[i];
            }
        }
        else
        {
            result = new gf2polynomial(b);
            for (i = 0; i < k; i++)
            {
                result.value[i] ^= value[i];
            }
        }
        // if we xor'ed some bits too many by proceeding blockwise,
        // restore them to zero:
        result.zerounusedbits();
        return result;
    }

    /**
     * computes the bitwise exclusive-or of this gf2polynomial and <i>b</i> and
     * stores the result in this gf2polynomial. <i>b</i> can be of different
     * size.
     *
     * @param b gf2polynomial
     */
    public void xorthisby(gf2polynomial b)
    {
        int i;
        for (i = 0; i < math.min(blocks, b.blocks); i++)
        {
            value[i] ^= b.value[i];
        }
        // if we xor'ed some bits too many by proceeding blockwise,
        // restore them to zero:
        zerounusedbits();
    }

    /**
     * if {@link #len} is not a multiple of the block size (32), some extra bits
     * of the last block might have been modified during a blockwise operation.
     * this method compensates for that by restoring these "extra" bits to zero.
     */
    private void zerounusedbits()
    {
        if ((len & 0x1f) != 0)
        {
            value[blocks - 1] &= reverserightmask[len & 0x1f];
        }
    }

    /**
     * sets the bit at position <i>i</i>.
     *
     * @param i int
     * @throws bitdoesnotexistexception if (<i>i</i> < 0) || (<i>i</i> > (len - 1))
     */
    public void setbit(int i)
        throws runtimeexception
    {
        if (i < 0 || i > (len - 1))
        {
            throw new runtimeexception();
        }
        if (i > (len - 1))
        {
            return;
        }
        value[i >>> 5] |= bitmask[i & 0x1f];
        return;
    }

    /**
     * returns the bit at position <i>i</i>.
     *
     * @param i int
     * @return the bit at position <i>i</i> if <i>i</i> is a valid position, 0
     *         otherwise.
     */
    public int getbit(int i)
    {
        if (i < 0 || i > (len - 1))
        {
            return 0;
        }
        return ((value[i >>> 5] & bitmask[i & 0x1f]) != 0) ? 1 : 0;
    }

    /**
     * resets the bit at position <i>i</i>.
     *
     * @param i int
     * @throws bitdoesnotexistexception if (<i>i</i> < 0) || (<i>i</i> > (len - 1))
     */
    public void resetbit(int i)
        throws runtimeexception
    {
        if (i < 0 || i > (len - 1))
        {
            throw new runtimeexception();
        }
        if (i > (len - 1))
        {
            return;
        }
        value[i >>> 5] &= ~bitmask[i & 0x1f];
    }

    /**
     * xors the bit at position <i>i</i>.
     *
     * @param i int
     * @throws bitdoesnotexistexception if (<i>i</i> < 0) || (<i>i</i> > (len - 1))
     */
    public void xorbit(int i)
        throws runtimeexception
    {
        if (i < 0 || i > (len - 1))
        {
            throw new runtimeexception();
        }
        if (i > (len - 1))
        {
            return;
        }
        value[i >>> 5] ^= bitmask[i & 0x1f];
    }

    /**
     * tests the bit at position <i>i</i>.
     *
     * @param i the position of the bit to be tested
     * @return true if the bit at position <i>i</i> is set (a(<i>i</i>) ==
     *         1). false if (<i>i</i> < 0) || (<i>i</i> > (len - 1))
     */
    public boolean testbit(int i)
    {
        if (i < 0 || i > (len - 1))
        {
            return false;
        }
        return (value[i >>> 5] & bitmask[i & 0x1f]) != 0;
    }

    /**
     * returns this gf2polynomial shift-left by 1 in a new gf2polynomial.
     *
     * @return a new gf2polynomial (this << 1)
     */
    public gf2polynomial shiftleft()
    {
        gf2polynomial result = new gf2polynomial(len + 1, value);
        int i;
        for (i = result.blocks - 1; i >= 1; i--)
        {
            result.value[i] <<= 1;
            result.value[i] |= result.value[i - 1] >>> 31;
        }
        result.value[0] <<= 1;
        return result;
    }

    /**
     * shifts-left this by one and enlarges the size of value if necesary.
     */
    public void shiftleftthis()
    {
        /** @todo this is untested. */
        int i;
        if ((len & 0x1f) == 0)
        { // check if blocks increases
            len += 1;
            blocks += 1;
            if (blocks > value.length)
            { // enlarge value
                int[] bs = new int[blocks];
                system.arraycopy(value, 0, bs, 0, value.length);
                value = null;
                value = bs;
            }
            for (i = blocks - 1; i >= 1; i--)
            {
                value[i] |= value[i - 1] >>> 31;
                value[i - 1] <<= 1;
            }
        }
        else
        {
            len += 1;
            for (i = blocks - 1; i >= 1; i--)
            {
                value[i] <<= 1;
                value[i] |= value[i - 1] >>> 31;
            }
            value[0] <<= 1;
        }
    }

    /**
     * returns this gf2polynomial shift-left by <i>k</i> in a new
     * gf2polynomial.
     *
     * @param k int
     * @return a new gf2polynomial (this << <i>k</i>)
     */
    public gf2polynomial shiftleft(int k)
    {
        // variant 2, requiring a modified shiftblocksleft(k)
        // in case of modification, consider a rename to doshiftblocksleft()
        // with an explicit note that this method assumes that the polynomial
        // has already been resized. or consider doing things inline.
        // construct the resulting polynomial of appropriate length:
        gf2polynomial result = new gf2polynomial(len + k, value);
        // shift left as many multiples of the block size as possible:
        if (k >= 32)
        {
            result.doshiftblocksleft(k >>> 5);
        }
        // shift left by the remaining (<32) amount:
        final int remaining = k & 0x1f;
        if (remaining != 0)
        {
            for (int i = result.blocks - 1; i >= 1; i--)
            {
                result.value[i] <<= remaining;
                result.value[i] |= result.value[i - 1] >>> (32 - remaining);
            }
            result.value[0] <<= remaining;
        }
        return result;
    }

    /**
     * shifts left b and adds the result to its a fast version of
     * <tt>this = add(b.shl(k));</tt>
     *
     * @param b gf2polynomial to shift and add to this
     * @param k the amount to shift
     * @see gf2npolynomialelement#inverteea
     */
    public void shiftleftaddthis(gf2polynomial b, int k)
    {
        if (k == 0)
        {
            addtothis(b);
            return;
        }
        int i;
        expandn(b.len + k);
        int d = k >>> 5;
        for (i = b.blocks - 1; i >= 0; i--)
        {
            if ((i + d + 1 < blocks) && ((k & 0x1f) != 0))
            {
                value[i + d + 1] ^= b.value[i] >>> (32 - (k & 0x1f));
            }
            value[i + d] ^= b.value[i] << (k & 0x1f);
        }
    }

    /**
     * shifts-left this gf2polynomial's value blockwise 1 block resulting in a
     * shift-left by 32.
     *
     * @see gf2polynomial#multiply
     */
    void shiftblocksleft()
    {
        blocks += 1;
        len += 32;
        if (blocks <= value.length)
        {
            int i;
            for (i = blocks - 1; i >= 1; i--)
            {
                value[i] = value[i - 1];
            }
            value[0] = 0x00;
        }
        else
        {
            int[] result = new int[blocks];
            system.arraycopy(value, 0, result, 1, blocks - 1);
            value = null;
            value = result;
        }
    }

    /**
     * shifts left this gf2polynomial's value blockwise <i>b</i> blocks
     * resulting in a shift-left by b*32. this method assumes that {@link #len}
     * and {@link #blocks} have already been updated to reflect the final state.
     *
     * @param b shift amount (in blocks)
     */
    private void doshiftblocksleft(int b)
    {
        if (blocks <= value.length)
        {
            int i;
            for (i = blocks - 1; i >= b; i--)
            {
                value[i] = value[i - b];
            }
            for (i = 0; i < b; i++)
            {
                value[i] = 0x00;
            }
        }
        else
        {
            int[] result = new int[blocks];
            system.arraycopy(value, 0, result, b, blocks - b);
            value = null;
            value = result;
        }
    }

    /**
     * returns this gf2polynomial shift-right by 1 in a new gf2polynomial.
     *
     * @return a new gf2polynomial (this << 1)
     */
    public gf2polynomial shiftright()
    {
        gf2polynomial result = new gf2polynomial(len - 1);
        int i;
        system.arraycopy(value, 0, result.value, 0, result.blocks);
        for (i = 0; i <= result.blocks - 2; i++)
        {
            result.value[i] >>>= 1;
            result.value[i] |= result.value[i + 1] << 31;
        }
        result.value[result.blocks - 1] >>>= 1;
        if (result.blocks < blocks)
        {
            result.value[result.blocks - 1] |= value[result.blocks] << 31;
        }
        return result;
    }

    /**
     * shifts-right this gf2polynomial by 1.
     */
    public void shiftrightthis()
    {
        int i;
        len -= 1;
        blocks = ((len - 1) >>> 5) + 1;
        for (i = 0; i <= blocks - 2; i++)
        {
            value[i] >>>= 1;
            value[i] |= value[i + 1] << 31;
        }
        value[blocks - 1] >>>= 1;
        if ((len & 0x1f) == 0)
        {
            value[blocks - 1] |= value[blocks] << 31;
        }
    }

}
