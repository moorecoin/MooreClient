package org.ripple.bouncycastle.pqc.math.linearalgebra;


import java.math.biginteger;
import java.util.random;

/**
 * this class implements an element of the finite field <i>gf(2<sup>n </sup>)</i>.
 * it is represented in an optimal normal basis representation and holds the
 * pointer <tt>mfield</tt> to its corresponding field.
 *
 * @see gf2nfield
 * @see gf2nelement
 */
public class gf2nonbelement
    extends gf2nelement
{

    // /////////////////////////////////////////////////////////////////////
    // member variables
    // /////////////////////////////////////////////////////////////////////

    private static final long[] mbitmask = new long[]{0x0000000000000001l,
        0x0000000000000002l, 0x0000000000000004l, 0x0000000000000008l,
        0x0000000000000010l, 0x0000000000000020l, 0x0000000000000040l,
        0x0000000000000080l, 0x0000000000000100l, 0x0000000000000200l,
        0x0000000000000400l, 0x0000000000000800l, 0x0000000000001000l,
        0x0000000000002000l, 0x0000000000004000l, 0x0000000000008000l,
        0x0000000000010000l, 0x0000000000020000l, 0x0000000000040000l,
        0x0000000000080000l, 0x0000000000100000l, 0x0000000000200000l,
        0x0000000000400000l, 0x0000000000800000l, 0x0000000001000000l,
        0x0000000002000000l, 0x0000000004000000l, 0x0000000008000000l,
        0x0000000010000000l, 0x0000000020000000l, 0x0000000040000000l,
        0x0000000080000000l, 0x0000000100000000l, 0x0000000200000000l,
        0x0000000400000000l, 0x0000000800000000l, 0x0000001000000000l,
        0x0000002000000000l, 0x0000004000000000l, 0x0000008000000000l,
        0x0000010000000000l, 0x0000020000000000l, 0x0000040000000000l,
        0x0000080000000000l, 0x0000100000000000l, 0x0000200000000000l,
        0x0000400000000000l, 0x0000800000000000l, 0x0001000000000000l,
        0x0002000000000000l, 0x0004000000000000l, 0x0008000000000000l,
        0x0010000000000000l, 0x0020000000000000l, 0x0040000000000000l,
        0x0080000000000000l, 0x0100000000000000l, 0x0200000000000000l,
        0x0400000000000000l, 0x0800000000000000l, 0x1000000000000000l,
        0x2000000000000000l, 0x4000000000000000l, 0x8000000000000000l};

    private static final long[] mmaxmask = new long[]{0x0000000000000001l,
        0x0000000000000003l, 0x0000000000000007l, 0x000000000000000fl,
        0x000000000000001fl, 0x000000000000003fl, 0x000000000000007fl,
        0x00000000000000ffl, 0x00000000000001ffl, 0x00000000000003ffl,
        0x00000000000007ffl, 0x0000000000000fffl, 0x0000000000001fffl,
        0x0000000000003fffl, 0x0000000000007fffl, 0x000000000000ffffl,
        0x000000000001ffffl, 0x000000000003ffffl, 0x000000000007ffffl,
        0x00000000000fffffl, 0x00000000001fffffl, 0x00000000003fffffl,
        0x00000000007fffffl, 0x0000000000ffffffl, 0x0000000001ffffffl,
        0x0000000003ffffffl, 0x0000000007ffffffl, 0x000000000fffffffl,
        0x000000001fffffffl, 0x000000003fffffffl, 0x000000007fffffffl,
        0x00000000ffffffffl, 0x00000001ffffffffl, 0x00000003ffffffffl,
        0x00000007ffffffffl, 0x0000000fffffffffl, 0x0000001fffffffffl,
        0x0000003fffffffffl, 0x0000007fffffffffl, 0x000000ffffffffffl,
        0x000001ffffffffffl, 0x000003ffffffffffl, 0x000007ffffffffffl,
        0x00000fffffffffffl, 0x00001fffffffffffl, 0x00003fffffffffffl,
        0x00007fffffffffffl, 0x0000ffffffffffffl, 0x0001ffffffffffffl,
        0x0003ffffffffffffl, 0x0007ffffffffffffl, 0x000fffffffffffffl,
        0x001fffffffffffffl, 0x003fffffffffffffl, 0x007fffffffffffffl,
        0x00ffffffffffffffl, 0x01ffffffffffffffl, 0x03ffffffffffffffl,
        0x07ffffffffffffffl, 0x0fffffffffffffffl, 0x1fffffffffffffffl,
        0x3fffffffffffffffl, 0x7fffffffffffffffl, 0xffffffffffffffffl};

    // miby64[j * 16 + i] = (j * 16 + i)/64
    // i =
    // 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15
    //
    private static final int[] miby64 = new int[]{
        // j =
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 0
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 1
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 2
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 3
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 4
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 5
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 6
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 7
        2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, // 8
        2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, // 9
        2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, // 10
        2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, // 11
        3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, // 12
        3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, // 13
        3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, // 14
        3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, // 15
        4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, // 16
        4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, // 17
        4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, // 18
        4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, // 19
        5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, // 20
        5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, // 21
        5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, // 22
        5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5 // 23
    };

    private static final int maxlong = 64;

    /**
     * holds the lenght of the polynomial with 64 bit sized fields.
     */
    private int mlength;

    /**
     * holds the value of mdeg % maxlong.
     */
    private int mbit;

    /**
     * holds this element in onb representation.
     */
    private long[] mpol;

    // /////////////////////////////////////////////////////////////////////
    // constructors
    // /////////////////////////////////////////////////////////////////////

    /**
     * construct a random element over the field <tt>gf2n</tt>, using the
     * specified source of randomness.
     *
     * @param gf2n the field
     * @param rand the source of randomness
     */
    public gf2nonbelement(gf2nonbfield gf2n, random rand)
    {
        mfield = gf2n;
        mdegree = mfield.getdegree();
        mlength = gf2n.getonblength();
        mbit = gf2n.getonbbit();
        mpol = new long[mlength];
        if (mlength > 1)
        {
            for (int j = 0; j < mlength - 1; j++)
            {
                mpol[j] = rand.nextlong();
            }
            long last = rand.nextlong();
            mpol[mlength - 1] = last >>> (maxlong - mbit);
        }
        else
        {
            mpol[0] = rand.nextlong();
            mpol[0] = mpol[0] >>> (maxlong - mbit);
        }
    }

    /**
     * construct a new gf2nonbelement from its encoding.
     *
     * @param gf2n the field
     * @param e    the encoded element
     */
    public gf2nonbelement(gf2nonbfield gf2n, byte[] e)
    {
        mfield = gf2n;
        mdegree = mfield.getdegree();
        mlength = gf2n.getonblength();
        mbit = gf2n.getonbbit();
        mpol = new long[mlength];
        assign(e);
    }

    /**
     * construct the element of the field <tt>gf2n</tt> with the specified
     * value <tt>val</tt>.
     *
     * @param gf2n the field
     * @param val  the value represented by a biginteger
     */
    public gf2nonbelement(gf2nonbfield gf2n, biginteger val)
    {
        mfield = gf2n;
        mdegree = mfield.getdegree();
        mlength = gf2n.getonblength();
        mbit = gf2n.getonbbit();
        mpol = new long[mlength];
        assign(val);
    }

    /**
     * construct the element of the field <tt>gf2n</tt> with the specified
     * value <tt>val</tt>.
     *
     * @param gf2n the field
     * @param val  the value in onb representation
     */
    private gf2nonbelement(gf2nonbfield gf2n, long[] val)
    {
        mfield = gf2n;
        mdegree = mfield.getdegree();
        mlength = gf2n.getonblength();
        mbit = gf2n.getonbbit();
        mpol = val;
    }

    // /////////////////////////////////////////////////////////////////////
    // pseudo-constructors
    // /////////////////////////////////////////////////////////////////////

    /**
     * copy constructor.
     *
     * @param gf2n the field
     */
    public gf2nonbelement(gf2nonbelement gf2n)
    {

        mfield = gf2n.mfield;
        mdegree = mfield.getdegree();
        mlength = ((gf2nonbfield)mfield).getonblength();
        mbit = ((gf2nonbfield)mfield).getonbbit();
        mpol = new long[mlength];
        assign(gf2n.getelement());
    }

    /**
     * create a new gf2nonbelement by cloning this gf2npolynomialelement.
     *
     * @return a copy of this element
     */
    public object clone()
    {
        return new gf2nonbelement(this);
    }

    /**
     * create the zero element.
     *
     * @param gf2n the finite field
     * @return the zero element in the given finite field
     */
    public static gf2nonbelement zero(gf2nonbfield gf2n)
    {
        long[] polynomial = new long[gf2n.getonblength()];
        return new gf2nonbelement(gf2n, polynomial);
    }

    /**
     * create the one element.
     *
     * @param gf2n the finite field
     * @return the one element in the given finite field
     */
    public static gf2nonbelement one(gf2nonbfield gf2n)
    {
        int mlength = gf2n.getonblength();
        long[] polynomial = new long[mlength];

        // fill mdegree coefficients with one's
        for (int i = 0; i < mlength - 1; i++)
        {
            polynomial[i] = 0xffffffffffffffffl;
        }
        polynomial[mlength - 1] = mmaxmask[gf2n.getonbbit() - 1];

        return new gf2nonbelement(gf2n, polynomial);
    }

    // /////////////////////////////////////////////////////////////////////
    // assignments
    // /////////////////////////////////////////////////////////////////////

    /**
     * assigns to this element the zero element
     */
    void assignzero()
    {
        mpol = new long[mlength];
    }

    /**
     * assigns to this element the one element
     */
    void assignone()
    {
        // fill mdegree coefficients with one's
        for (int i = 0; i < mlength - 1; i++)
        {
            mpol[i] = 0xffffffffffffffffl;
        }
        mpol[mlength - 1] = mmaxmask[mbit - 1];
    }

    /**
     * assigns to this element the value <tt>val</tt>.
     *
     * @param val the value represented by a biginteger
     */
    private void assign(biginteger val)
    {
        assign(val.tobytearray());
    }

    /**
     * assigns to this element the value <tt>val</tt>.
     *
     * @param val the value in onb representation
     */
    private void assign(long[] val)
    {
        system.arraycopy(val, 0, mpol, 0, mlength);
    }

    /**
     * assigns to this element the value <tt>val</tt>. first: inverting the
     * order of val into reversed[]. that means: reversed[0] = val[length - 1],
     * ..., reversed[reversed.length - 1] = val[0]. second: mpol[0] = sum{i = 0,
     * ... 7} (val[i]<<(i*8)) .... mpol[1] = sum{i = 8, ... 15} (val[i]<<(i*8))
     *
     * @param val the value in onb representation
     */
    private void assign(byte[] val)
    {
        int j;
        mpol = new long[mlength];
        for (j = 0; j < val.length; j++)
        {
            mpol[j >>> 3] |= (val[val.length - 1 - j] & 0x00000000000000ffl) << ((j & 0x07) << 3);
        }
    }

    // /////////////////////////////////////////////////////////////////
    // comparison
    // /////////////////////////////////////////////////////////////////

    /**
     * checks whether this element is zero.
     *
     * @return <tt>true</tt> if <tt>this</tt> is the zero element
     */
    public boolean iszero()
    {

        boolean result = true;

        for (int i = 0; i < mlength && result; i++)
        {
            result = result && ((mpol[i] & 0xffffffffffffffffl) == 0);
        }

        return result;
    }

    /**
     * checks whether this element is one.
     *
     * @return <tt>true</tt> if <tt>this</tt> is the one element
     */
    public boolean isone()
    {

        boolean result = true;

        for (int i = 0; i < mlength - 1 && result; i++)
        {
            result = result
                && ((mpol[i] & 0xffffffffffffffffl) == 0xffffffffffffffffl);
        }

        if (result)
        {
            result = result
                && ((mpol[mlength - 1] & mmaxmask[mbit - 1]) == mmaxmask[mbit - 1]);
        }

        return result;
    }

    /**
     * compare this element with another object.
     *
     * @param other the other object
     * @return <tt>true</tt> if the two objects are equal, <tt>false</tt>
     *         otherwise
     */
    public boolean equals(object other)
    {
        if (other == null || !(other instanceof gf2nonbelement))
        {
            return false;
        }

        gf2nonbelement otherelem = (gf2nonbelement)other;

        for (int i = 0; i < mlength; i++)
        {
            if (mpol[i] != otherelem.mpol[i])
            {
                return false;
            }
        }

        return true;
    }

    /**
     * @return the hash code of this element
     */
    public int hashcode()
    {
        return mpol.hashcode();
    }

    // /////////////////////////////////////////////////////////////////////
    // access
    // /////////////////////////////////////////////////////////////////////

    /**
     * returns whether the highest bit of the bit representation is set
     *
     * @return true, if the highest bit of mpol is set, false, otherwise
     */
    public boolean testrightmostbit()
    {
        // due to the reverse bit order (compared to 1363) this method returns
        // the value of the leftmost bit
        return (mpol[mlength - 1] & mbitmask[mbit - 1]) != 0l;
    }

    /**
     * checks whether the indexed bit of the bit representation is set. warning:
     * gf2nonbelement currently stores its bits in reverse order (compared to
     * 1363) !!!
     *
     * @param index the index of the bit to test
     * @return <tt>true</tt> if the indexed bit of mpol is set, <tt>false</tt>
     *         otherwise.
     */
    boolean testbit(int index)
    {
        if (index < 0 || index > mdegree)
        {
            return false;
        }
        long test = mpol[index >>> 6] & mbitmask[index & 0x3f];
        return test != 0x0l;
    }

    /**
     * @return this element in its onb representation
     */
    private long[] getelement()
    {

        long[] result = new long[mpol.length];
        system.arraycopy(mpol, 0, result, 0, mpol.length);

        return result;
    }

    /**
     * returns the onb representation of this element. the bit-order is
     * exchanged (according to 1363)!
     *
     * @return this element in its representation and reverse bit-order
     */
    private long[] getelementreverseorder()
    {
        long[] result = new long[mpol.length];
        for (int i = 0; i < mdegree; i++)
        {
            if (testbit(mdegree - i - 1))
            {
                result[i >>> 6] |= mbitmask[i & 0x3f];
            }
        }
        return result;
    }

    /**
     * reverses the bit-order in this element(according to 1363). this is a
     * hack!
     */
    void reverseorder()
    {
        mpol = getelementreverseorder();
    }

    // /////////////////////////////////////////////////////////////////////
    // arithmetic
    // /////////////////////////////////////////////////////////////////////

    /**
     * compute the sum of this element and <tt>addend</tt>.
     *
     * @param addend the addend
     * @return <tt>this + other</tt> (newly created)
     * @throws differentfieldsexception if the elements are of different fields.
     */
    public gfelement add(gfelement addend)
        throws runtimeexception
    {
        gf2nonbelement result = new gf2nonbelement(this);
        result.addtothis(addend);
        return result;
    }

    /**
     * compute <tt>this + addend</tt> (overwrite <tt>this</tt>).
     *
     * @param addend the addend
     * @throws differentfieldsexception if the elements are of different fields.
     */
    public void addtothis(gfelement addend)
        throws runtimeexception
    {
        if (!(addend instanceof gf2nonbelement))
        {
            throw new runtimeexception();
        }
        if (!mfield.equals(((gf2nonbelement)addend).mfield))
        {
            throw new runtimeexception();
        }

        for (int i = 0; i < mlength; i++)
        {
            mpol[i] ^= ((gf2nonbelement)addend).mpol[i];
        }
    }

    /**
     * returns <tt>this</tt> element + 1.
     *
     * @return <tt>this</tt> + 1
     */
    public gf2nelement increase()
    {
        gf2nonbelement result = new gf2nonbelement(this);
        result.increasethis();
        return result;
    }

    /**
     * increases <tt>this</tt> element.
     */
    public void increasethis()
    {
        addtothis(one((gf2nonbfield)mfield));
    }

    /**
     * compute the product of this element and <tt>factor</tt>.
     *
     * @param factor the factor
     * @return <tt>this * factor</tt> (newly created)
     * @throws differentfieldsexception if the elements are of different fields.
     */
    public gfelement multiply(gfelement factor)
        throws runtimeexception
    {
        gf2nonbelement result = new gf2nonbelement(this);
        result.multiplythisby(factor);
        return result;
    }

    /**
     * compute <tt>this * factor</tt> (overwrite <tt>this</tt>).
     *
     * @param factor the factor
     * @throws differentfieldsexception if the elements are of different fields.
     */
    public void multiplythisby(gfelement factor)
        throws runtimeexception
    {

        if (!(factor instanceof gf2nonbelement))
        {
            throw new runtimeexception("the elements have different"
                + " representation: not yet" + " implemented");
        }
        if (!mfield.equals(((gf2nonbelement)factor).mfield))
        {
            throw new runtimeexception();
        }

        if (equals(factor))
        {
            squarethis();
        }
        else
        {

            long[] a = mpol;
            long[] b = ((gf2nonbelement)factor).mpol;
            long[] c = new long[mlength];

            int[][] m = ((gf2nonbfield)mfield).mmult;

            int degf, degb, s, fielda, fieldb, bita, bitb;
            degf = mlength - 1;
            degb = mbit - 1;
            s = 0;

            long twotomaxlongm1 = mbitmask[maxlong - 1];
            long twotodegb = mbitmask[degb];

            boolean old, now;

            // the product c of a and b (a*b = c) is calculated in mdegree
            // cicles
            // in every cicle one coefficient of c is calculated and stored
            // k indicates the coefficient
            //
            for (int k = 0; k < mdegree; k++)
            {

                s = 0;

                for (int i = 0; i < mdegree; i++)
                {

                    // fielda = i / maxlong
                    //
                    fielda = miby64[i];

                    // bita = i % maxlong
                    //
                    bita = i & (maxlong - 1);

                    // fieldb = m[i][0] / maxlong
                    //
                    fieldb = miby64[m[i][0]];

                    // bitb = m[i][0] % maxlong
                    //
                    bitb = m[i][0] & (maxlong - 1);

                    if ((a[fielda] & mbitmask[bita]) != 0)
                    {

                        if ((b[fieldb] & mbitmask[bitb]) != 0)
                        {
                            s ^= 1;
                        }

                        if (m[i][1] != -1)
                        {

                            // fieldb = m[i][1] / maxlong
                            //
                            fieldb = miby64[m[i][1]];

                            // bitb = m[i][1] % maxlong
                            //
                            bitb = m[i][1] & (maxlong - 1);

                            if ((b[fieldb] & mbitmask[bitb]) != 0)
                            {
                                s ^= 1;
                            }

                        }
                    }
                }
                fielda = miby64[k];
                bita = k & (maxlong - 1);

                if (s != 0)
                {
                    c[fielda] ^= mbitmask[bita];
                }

                // circular shift of x and y one bit to the right,
                // respectively.

                if (mlength > 1)
                {

                    // shift x.
                    //
                    old = (a[degf] & 1) == 1;

                    for (int i = degf - 1; i >= 0; i--)
                    {
                        now = (a[i] & 1) != 0;

                        a[i] = a[i] >>> 1;

                        if (old)
                        {
                            a[i] ^= twotomaxlongm1;
                        }

                        old = now;
                    }
                    a[degf] = a[degf] >>> 1;

                    if (old)
                    {
                        a[degf] ^= twotodegb;
                    }

                    // shift y.
                    //
                    old = (b[degf] & 1) == 1;

                    for (int i = degf - 1; i >= 0; i--)
                    {
                        now = (b[i] & 1) != 0;

                        b[i] = b[i] >>> 1;

                        if (old)
                        {
                            b[i] ^= twotomaxlongm1;
                        }

                        old = now;
                    }

                    b[degf] = b[degf] >>> 1;

                    if (old)
                    {
                        b[degf] ^= twotodegb;
                    }
                }
                else
                {
                    old = (a[0] & 1) == 1;
                    a[0] = a[0] >>> 1;

                    if (old)
                    {
                        a[0] ^= twotodegb;
                    }

                    old = (b[0] & 1) == 1;
                    b[0] = b[0] >>> 1;

                    if (old)
                    {
                        b[0] ^= twotodegb;
                    }
                }
            }
            assign(c);
        }
    }

    /**
     * returns <tt>this</tt> element to the power of 2.
     *
     * @return <tt>this</tt><sup>2</sup>
     */
    public gf2nelement square()
    {
        gf2nonbelement result = new gf2nonbelement(this);
        result.squarethis();
        return result;
    }

    /**
     * squares <tt>this</tt> element.
     */
    public void squarethis()
    {

        long[] pol = getelement();

        int f = mlength - 1;
        int b = mbit - 1;

        // shift the coefficients one bit to the left.
        //
        long twotomaxlongm1 = mbitmask[maxlong - 1];
        boolean old, now;

        old = (pol[f] & mbitmask[b]) != 0;

        for (int i = 0; i < f; i++)
        {

            now = (pol[i] & twotomaxlongm1) != 0;

            pol[i] = pol[i] << 1;

            if (old)
            {
                pol[i] ^= 1;
            }

            old = now;
        }
        now = (pol[f] & mbitmask[b]) != 0;

        pol[f] = pol[f] << 1;

        if (old)
        {
            pol[f] ^= 1;
        }

        // set the bit with index mdegree to zero.
        //
        if (now)
        {
            pol[f] ^= mbitmask[b + 1];
        }

        assign(pol);
    }

    /**
     * compute the multiplicative inverse of this element.
     *
     * @return <tt>this<sup>-1</sup></tt> (newly created)
     * @throws arithmeticexception if <tt>this</tt> is the zero element.
     */
    public gfelement invert()
        throws arithmeticexception
    {
        gf2nonbelement result = new gf2nonbelement(this);
        result.invertthis();
        return result;
    }

    /**
     * multiplicatively invert of this element (overwrite <tt>this</tt>).
     *
     * @throws arithmeticexception if <tt>this</tt> is the zero element.
     */
    public void invertthis()
        throws arithmeticexception
    {

        if (iszero())
        {
            throw new arithmeticexception();
        }
        int r = 31; // mdegree kann nur 31 bits lang sein!!!

        // bitlaenge von mdegree:
        for (boolean found = false; !found && r >= 0; r--)
        {

            if (((mdegree - 1) & mbitmask[r]) != 0)
            {
                found = true;
            }
        }
        r++;

        gf2nelement m = zero((gf2nonbfield)mfield);
        gf2nelement n = new gf2nonbelement(this);

        int k = 1;

        for (int i = r - 1; i >= 0; i--)
        {
            m = (gf2nelement)n.clone();
            for (int j = 1; j <= k; j++)
            {
                m.squarethis();
            }

            n.multiplythisby(m);

            k <<= 1;
            if (((mdegree - 1) & mbitmask[i]) != 0)
            {
                n.squarethis();

                n.multiplythisby(this);

                k++;
            }
        }
        n.squarethis();
    }

    /**
     * returns the root of<tt>this</tt> element.
     *
     * @return <tt>this</tt><sup>1/2</sup>
     */
    public gf2nelement squareroot()
    {
        gf2nonbelement result = new gf2nonbelement(this);
        result.squarerootthis();
        return result;
    }

    /**
     * square roots <tt>this</tt> element.
     */
    public void squarerootthis()
    {

        long[] pol = getelement();

        int f = mlength - 1;
        int b = mbit - 1;

        // shift the coefficients one bit to the right.
        //
        long twotomaxlongm1 = mbitmask[maxlong - 1];
        boolean old, now;

        old = (pol[0] & 1) != 0;

        for (int i = f; i >= 0; i--)
        {
            now = (pol[i] & 1) != 0;
            pol[i] = pol[i] >>> 1;

            if (old)
            {
                if (i == f)
                {
                    pol[i] ^= mbitmask[b];
                }
                else
                {
                    pol[i] ^= twotomaxlongm1;
                }
            }
            old = now;
        }
        assign(pol);
    }

    /**
     * returns the trace of this element.
     *
     * @return the trace of this element
     */
    public int trace()
    {

        // trace = sum of coefficients
        //

        int result = 0;

        int max = mlength - 1;

        for (int i = 0; i < max; i++)
        {

            for (int j = 0; j < maxlong; j++)
            {

                if ((mpol[i] & mbitmask[j]) != 0)
                {
                    result ^= 1;
                }
            }
        }

        int b = mbit;

        for (int j = 0; j < b; j++)
        {

            if ((mpol[max] & mbitmask[j]) != 0)
            {
                result ^= 1;
            }
        }
        return result;
    }

    /**
     * solves a quadratic equation.<br>
     * let z<sup>2</sup> + z = <tt>this</tt>. then this method returns z.
     *
     * @return z with z<sup>2</sup> + z = <tt>this</tt>
     * @throws nosolutionexception if z<sup>2</sup> + z = <tt>this</tt> does not have a
     * solution
     */
    public gf2nelement solvequadraticequation()
        throws runtimeexception
    {

        if (trace() == 1)
        {
            throw new runtimeexception();
        }

        long twotomaxlongm1 = mbitmask[maxlong - 1];
        long zero = 0l;
        long one = 1l;

        long[] p = new long[mlength];
        long z = 0l;
        int j = 1;
        for (int i = 0; i < mlength - 1; i++)
        {

            for (j = 1; j < maxlong; j++)
            {

                //
                if (!((((mbitmask[j] & mpol[i]) != zero) && ((z & mbitmask[j - 1]) != zero)) || (((mpol[i] & mbitmask[j]) == zero) && ((z & mbitmask[j - 1]) == zero))))
                {
                    z ^= mbitmask[j];
                }
            }
            p[i] = z;

            if (((twotomaxlongm1 & z) != zero && (one & mpol[i + 1]) == one)
                || ((twotomaxlongm1 & z) == zero && (one & mpol[i + 1]) == zero))
            {
                z = zero;
            }
            else
            {
                z = one;
            }
        }

        int b = mdegree & (maxlong - 1);

        long lastlong = mpol[mlength - 1];

        for (j = 1; j < b; j++)
        {
            if (!((((mbitmask[j] & lastlong) != zero) && ((mbitmask[j - 1] & z) != zero)) || (((mbitmask[j] & lastlong) == zero) && ((mbitmask[j - 1] & z) == zero))))
            {
                z ^= mbitmask[j];
            }
        }
        p[mlength - 1] = z;
        return new gf2nonbelement((gf2nonbfield)mfield, p);
    }

    // /////////////////////////////////////////////////////////////////
    // conversion
    // /////////////////////////////////////////////////////////////////

    /**
     * returns a string representation of this element.
     *
     * @return string representation of this element with the specified radix
     */
    public string tostring()
    {
        return tostring(16);
    }

    /**
     * returns a string representation of this element. <tt>radix</tt>
     * specifies the radix of the string representation.<br>
     * note: only <tt>radix = 2</tt> or <tt>radix = 16</tt> is implemented>
     *
     * @param radix specifies the radix of the string representation
     * @return string representation of this element with the specified radix
     */
    public string tostring(int radix)
    {
        string s = "";

        long[] a = getelement();
        int b = mbit;

        if (radix == 2)
        {

            for (int j = b - 1; j >= 0; j--)
            {
                if ((a[a.length - 1] & ((long)1 << j)) == 0)
                {
                    s += "0";
                }
                else
                {
                    s += "1";
                }
            }

            for (int i = a.length - 2; i >= 0; i--)
            {
                for (int j = maxlong - 1; j >= 0; j--)
                {
                    if ((a[i] & mbitmask[j]) == 0)
                    {
                        s += "0";
                    }
                    else
                    {
                        s += "1";
                    }
                }
            }
        }
        else if (radix == 16)
        {
            final char[] hex_chars = {'0', '1', '2', '3', '4', '5', '6', '7',
                '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
            for (int i = a.length - 1; i >= 0; i--)
            {
                s += hex_chars[(int)(a[i] >>> 60) & 0x0f];
                s += hex_chars[(int)(a[i] >>> 56) & 0x0f];
                s += hex_chars[(int)(a[i] >>> 52) & 0x0f];
                s += hex_chars[(int)(a[i] >>> 48) & 0x0f];
                s += hex_chars[(int)(a[i] >>> 44) & 0x0f];
                s += hex_chars[(int)(a[i] >>> 40) & 0x0f];
                s += hex_chars[(int)(a[i] >>> 36) & 0x0f];
                s += hex_chars[(int)(a[i] >>> 32) & 0x0f];
                s += hex_chars[(int)(a[i] >>> 28) & 0x0f];
                s += hex_chars[(int)(a[i] >>> 24) & 0x0f];
                s += hex_chars[(int)(a[i] >>> 20) & 0x0f];
                s += hex_chars[(int)(a[i] >>> 16) & 0x0f];
                s += hex_chars[(int)(a[i] >>> 12) & 0x0f];
                s += hex_chars[(int)(a[i] >>> 8) & 0x0f];
                s += hex_chars[(int)(a[i] >>> 4) & 0x0f];
                s += hex_chars[(int)(a[i]) & 0x0f];
                s += " ";
            }
        }
        return s;
    }

    /**
     * returns this element as flexibigint. the conversion is <a href =
     * "http://grouper.ieee.org/groups/1363/">p1363</a>-conform.
     *
     * @return this element as biginteger
     */
    public biginteger toflexibigint()
    {
        /** @todo this method does not reverse the bit-order as it should!!! */

        return new biginteger(1, tobytearray());
    }

    /**
     * returns this element as byte array. the conversion is <a href =
     * "http://grouper.ieee.org/groups/1363/">p1363</a>-conform.
     *
     * @return this element as byte array
     */
    public byte[] tobytearray()
    {
        /** @todo this method does not reverse the bit-order as it should!!! */

        int k = ((mdegree - 1) >> 3) + 1;
        byte[] result = new byte[k];
        int i;
        for (i = 0; i < k; i++)
        {
            result[k - i - 1] = (byte)((mpol[i >>> 3] & (0x00000000000000ffl << ((i & 0x07) << 3))) >>> ((i & 0x07) << 3));
        }
        return result;
    }

}
