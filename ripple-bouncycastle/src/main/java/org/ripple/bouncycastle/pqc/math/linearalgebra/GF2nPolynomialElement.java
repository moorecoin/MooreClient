package org.ripple.bouncycastle.pqc.math.linearalgebra;


import java.math.biginteger;
import java.util.random;


/**
 * this class implements elements of finite binary fields <i>gf(2<sup>n</sup>)</i>
 * using polynomial representation. for more information on the arithmetic see
 * for example ieee standard 1363 or <a
 * href=http://www.certicom.com/research/online.html> certicom online-tutorial</a>.
 *
 * @see "gf2nfield"
 * @see gf2npolynomialfield
 * @see gf2nonbelement
 * @see gf2polynomial
 */
public class gf2npolynomialelement
    extends gf2nelement
{

    // pre-computed bitmask for fast masking, bitmask[a]=0x1 << a
    private static final int[] bitmask = {0x00000001, 0x00000002, 0x00000004,
        0x00000008, 0x00000010, 0x00000020, 0x00000040, 0x00000080,
        0x00000100, 0x00000200, 0x00000400, 0x00000800, 0x00001000,
        0x00002000, 0x00004000, 0x00008000, 0x00010000, 0x00020000,
        0x00040000, 0x00080000, 0x00100000, 0x00200000, 0x00400000,
        0x00800000, 0x01000000, 0x02000000, 0x04000000, 0x08000000,
        0x10000000, 0x20000000, 0x40000000, 0x80000000, 0x00000000};

    // the used gf2polynomial which stores the coefficients
    private gf2polynomial polynomial;

    /**
     * create a new random gf2npolynomialelement using the given field and
     * source of randomness.
     *
     * @param f    the gf2nfield to use
     * @param rand the source of randomness
     */
    public gf2npolynomialelement(gf2npolynomialfield f, random rand)
    {
        mfield = f;
        mdegree = mfield.getdegree();
        polynomial = new gf2polynomial(mdegree);
        randomize(rand);
    }

    /**
     * creates a new gf2npolynomialelement using the given field and bitstring.
     *
     * @param f  the gf2npolynomialfield to use
     * @param bs the desired value as bitstring
     */
    public gf2npolynomialelement(gf2npolynomialfield f, gf2polynomial bs)
    {
        mfield = f;
        mdegree = mfield.getdegree();
        polynomial = new gf2polynomial(bs);
        polynomial.expandn(mdegree);
    }

    /**
     * creates a new gf2npolynomialelement using the given field <i>f</i> and
     * byte[] <i>os</i> as value. the conversion is done according to 1363.
     *
     * @param f  the gf2nfield to use
     * @param os the octet string to assign to this gf2npolynomialelement
     * @see "p1363 5.5.5 p23, os2fep/os2bsp"
     */
    public gf2npolynomialelement(gf2npolynomialfield f, byte[] os)
    {
        mfield = f;
        mdegree = mfield.getdegree();
        polynomial = new gf2polynomial(mdegree, os);
        polynomial.expandn(mdegree);
    }

    /**
     * creates a new gf2npolynomialelement using the given field <i>f</i> and
     * int[] <i>is</i> as value.
     *
     * @param f  the gf2nfield to use
     * @param is the integer string to assign to this gf2npolynomialelement
     */
    public gf2npolynomialelement(gf2npolynomialfield f, int[] is)
    {
        mfield = f;
        mdegree = mfield.getdegree();
        polynomial = new gf2polynomial(mdegree, is);
        polynomial.expandn(f.mdegree);
    }

    /**
     * creates a new gf2npolynomialelement by cloning the given
     * gf2npolynomialelement <i>b</i>.
     *
     * @param other the gf2npolynomialelement to clone
     */
    public gf2npolynomialelement(gf2npolynomialelement other)
    {
        mfield = other.mfield;
        mdegree = other.mdegree;
        polynomial = new gf2polynomial(other.polynomial);
    }

    // /////////////////////////////////////////////////////////////////////
    // pseudo-constructors
    // /////////////////////////////////////////////////////////////////////

    /**
     * creates a new gf2npolynomialelement by cloning this
     * gf2npolynomialelement.
     *
     * @return a copy of this element
     */
    public object clone()
    {
        return new gf2npolynomialelement(this);
    }

    // /////////////////////////////////////////////////////////////////////
    // assignments
    // /////////////////////////////////////////////////////////////////////

    /**
     * assigns the value 'zero' to this polynomial.
     */
    void assignzero()
    {
        polynomial.assignzero();
    }

    /**
     * create the zero element.
     *
     * @param f the finite field
     * @return the zero element in the given finite field
     */
    public static gf2npolynomialelement zero(gf2npolynomialfield f)
    {
        gf2polynomial polynomial = new gf2polynomial(f.getdegree());
        return new gf2npolynomialelement(f, polynomial);
    }

    /**
     * create the one element.
     *
     * @param f the finite field
     * @return the one element in the given finite field
     */
    public static gf2npolynomialelement one(gf2npolynomialfield f)
    {
        gf2polynomial polynomial = new gf2polynomial(f.getdegree(),
            new int[]{1});
        return new gf2npolynomialelement(f, polynomial);
    }

    /**
     * assigns the value 'one' to this polynomial.
     */
    void assignone()
    {
        polynomial.assignone();
    }

    /**
     * assign a random value to this gf2npolynomialelement using the specified
     * source of randomness.
     *
     * @param rand the source of randomness
     */
    private void randomize(random rand)
    {
        polynomial.expandn(mdegree);
        polynomial.randomize(rand);
    }

    // /////////////////////////////////////////////////////////////////////
    // comparison
    // /////////////////////////////////////////////////////////////////////

    /**
     * checks whether this element is zero.
     *
     * @return <tt>true</tt> if <tt>this</tt> is the zero element
     */
    public boolean iszero()
    {
        return polynomial.iszero();
    }

    /**
     * tests if the gf2npolynomialelement has 'one' as value.
     *
     * @return true if <i>this</i> equals one (this == 1)
     */
    public boolean isone()
    {
        return polynomial.isone();
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
        if (other == null || !(other instanceof gf2npolynomialelement))
        {
            return false;
        }
        gf2npolynomialelement otherelem = (gf2npolynomialelement)other;

        if (mfield != otherelem.mfield)
        {
            if (!mfield.getfieldpolynomial().equals(
                otherelem.mfield.getfieldpolynomial()))
            {
                return false;
            }
        }

        return polynomial.equals(otherelem.polynomial);
    }

    /**
     * @return the hash code of this element
     */
    public int hashcode()
    {
        return mfield.hashcode() + polynomial.hashcode();
    }

    // /////////////////////////////////////////////////////////////////////
    // access
    // /////////////////////////////////////////////////////////////////////

    /**
     * returns the value of this gf2npolynomialelement in a new bitstring.
     *
     * @return the value of this gf2npolynomialelement in a new bitstring
     */
    private gf2polynomial getgf2polynomial()
    {
        return new gf2polynomial(polynomial);
    }

    /**
     * checks whether the indexed bit of the bit representation is set.
     *
     * @param index the index of the bit to test
     * @return <tt>true</tt> if the indexed bit is set
     */
    boolean testbit(int index)
    {
        return polynomial.testbit(index);
    }

    /**
     * returns whether the rightmost bit of the bit representation is set. this
     * is needed for data conversion according to 1363.
     *
     * @return true if the rightmost bit of this element is set
     */
    public boolean testrightmostbit()
    {
        return polynomial.testbit(0);
    }

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
        gf2npolynomialelement result = new gf2npolynomialelement(this);
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
        if (!(addend instanceof gf2npolynomialelement))
        {
            throw new runtimeexception();
        }
        if (!mfield.equals(((gf2npolynomialelement)addend).mfield))
        {
            throw new runtimeexception();
        }
        polynomial.addtothis(((gf2npolynomialelement)addend).polynomial);
    }

    /**
     * returns <tt>this</tt> element + 'one".
     *
     * @return <tt>this</tt> + 'one'
     */
    public gf2nelement increase()
    {
        gf2npolynomialelement result = new gf2npolynomialelement(this);
        result.increasethis();
        return result;
    }

    /**
     * increases this element by 'one'.
     */
    public void increasethis()
    {
        polynomial.increasethis();
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
        gf2npolynomialelement result = new gf2npolynomialelement(this);
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
        if (!(factor instanceof gf2npolynomialelement))
        {
            throw new runtimeexception();
        }
        if (!mfield.equals(((gf2npolynomialelement)factor).mfield))
        {
            throw new runtimeexception();
        }
        if (equals(factor))
        {
            squarethis();
            return;
        }
        polynomial = polynomial
            .multiply(((gf2npolynomialelement)factor).polynomial);
        reducethis();
    }

    /**
     * compute the multiplicative inverse of this element.
     *
     * @return <tt>this<sup>-1</sup></tt> (newly created)
     * @throws arithmeticexception if <tt>this</tt> is the zero element.
     * @see gf2npolynomialelement#invertmaia
     * @see gf2npolynomialelement#inverteea
     * @see gf2npolynomialelement#invertsquare
     */
    public gfelement invert()
        throws arithmeticexception
    {
        return invertmaia();
    }

    /**
     * calculates the multiplicative inverse of <i>this</i> and returns the
     * result in a new gf2npolynomialelement.
     *
     * @return <i>this</i>^(-1)
     * @throws arithmeticexception if <i>this</i> equals zero
     */
    public gf2npolynomialelement inverteea()
        throws arithmeticexception
    {
        if (iszero())
        {
            throw new arithmeticexception();
        }
        gf2polynomial b = new gf2polynomial(mdegree + 32, "one");
        b.reducen();
        gf2polynomial c = new gf2polynomial(mdegree + 32);
        c.reducen();
        gf2polynomial u = getgf2polynomial();
        gf2polynomial v = mfield.getfieldpolynomial();
        gf2polynomial h;
        int j;
        u.reducen();
        while (!u.isone())
        {
            u.reducen();
            v.reducen();
            j = u.getlength() - v.getlength();
            if (j < 0)
            {
                h = u;
                u = v;
                v = h;
                h = b;
                b = c;
                c = h;
                j = -j;
                c.reducen(); // this increases the performance
            }
            u.shiftleftaddthis(v, j);
            b.shiftleftaddthis(c, j);
        }
        b.reducen();
        return new gf2npolynomialelement((gf2npolynomialfield)mfield, b);
    }

    /**
     * calculates the multiplicative inverse of <i>this</i> and returns the
     * result in a new gf2npolynomialelement.
     *
     * @return <i>this</i>^(-1)
     * @throws arithmeticexception if <i>this</i> equals zero
     */
    public gf2npolynomialelement invertsquare()
        throws arithmeticexception
    {
        gf2npolynomialelement n;
        gf2npolynomialelement u;
        int i, j, k, b;

        if (iszero())
        {
            throw new arithmeticexception();
        }
        // b = (n-1)
        b = mfield.getdegree() - 1;
        // n = a
        n = new gf2npolynomialelement(this);
        n.polynomial.expandn((mdegree << 1) + 32); // increase performance
        n.polynomial.reducen();
        // k = 1
        k = 1;

        // for i = (r-1) downto 0 do, r=bitlength(b)
        for (i = integerfunctions.floorlog(b) - 1; i >= 0; i--)
        {
            // u = n
            u = new gf2npolynomialelement(n);
            // for j = 1 to k do
            for (j = 1; j <= k; j++)
            {
                // u = u^2
                u.squarethisprecalc();
            }
            // n = nu
            n.multiplythisby(u);
            // k = 2k
            k <<= 1;
            // if b(i)==1
            if ((b & bitmask[i]) != 0)
            {
                // n = n^2 * b
                n.squarethisprecalc();
                n.multiplythisby(this);
                // k = k+1
                k += 1;
            }
        }

        // outpur n^2
        n.squarethisprecalc();
        return n;
    }

    /**
     * calculates the multiplicative inverse of <i>this</i> using the modified
     * almost inverse algorithm and returns the result in a new
     * gf2npolynomialelement.
     *
     * @return <i>this</i>^(-1)
     * @throws arithmeticexception if <i>this</i> equals zero
     */
    public gf2npolynomialelement invertmaia()
        throws arithmeticexception
    {
        if (iszero())
        {
            throw new arithmeticexception();
        }
        gf2polynomial b = new gf2polynomial(mdegree, "one");
        gf2polynomial c = new gf2polynomial(mdegree);
        gf2polynomial u = getgf2polynomial();
        gf2polynomial v = mfield.getfieldpolynomial();
        gf2polynomial h;
        while (true)
        {
            while (!u.testbit(0))
            { // x|u (x divides u)
                u.shiftrightthis(); // u = u / x
                if (!b.testbit(0))
                {
                    b.shiftrightthis();
                }
                else
                {
                    b.addtothis(mfield.getfieldpolynomial());
                    b.shiftrightthis();
                }
            }
            if (u.isone())
            {
                return new gf2npolynomialelement((gf2npolynomialfield)mfield,
                    b);
            }
            u.reducen();
            v.reducen();
            if (u.getlength() < v.getlength())
            {
                h = u;
                u = v;
                v = h;
                h = b;
                b = c;
                c = h;
            }
            u.addtothis(v);
            b.addtothis(c);
        }
    }

    /**
     * this method is used internally to map the square()-calls within
     * gf2npolynomialelement to one of the possible squaring methods.
     *
     * @return <tt>this<sup>2</sup></tt> (newly created)
     * @see gf2npolynomialelement#squareprecalc
     */
    public gf2nelement square()
    {
        return squareprecalc();
    }

    /**
     * this method is used internally to map the square()-calls within
     * gf2npolynomialelement to one of the possible squaring methods.
     */
    public void squarethis()
    {
        squarethisprecalc();
    }

    /**
     * squares this gf2npolynomialelement using gf2nfield's squaring matrix.
     * this is supposed to be fast when using a polynomial (no tri- or
     * pentanomial) as fieldpolynomial. use squareprecalc when using a tri- or
     * pentanomial as fieldpolynomial instead.
     *
     * @return <tt>this<sup>2</sup></tt> (newly created)
     * @see gf2polynomial#vectormult
     * @see gf2npolynomialelement#squareprecalc
     * @see gf2npolynomialelement#squarebitwise
     */
    public gf2npolynomialelement squarematrix()
    {
        gf2npolynomialelement result = new gf2npolynomialelement(this);
        result.squarethismatrix();
        result.reducethis();
        return result;
    }

    /**
     * squares this gf2npolynomialelement using gf2nfields squaring matrix. this
     * is supposed to be fast when using a polynomial (no tri- or pentanomial)
     * as fieldpolynomial. use squareprecalc when using a tri- or pentanomial as
     * fieldpolynomial instead.
     *
     * @see gf2polynomial#vectormult
     * @see gf2npolynomialelement#squareprecalc
     * @see gf2npolynomialelement#squarebitwise
     */
    public void squarethismatrix()
    {
        gf2polynomial result = new gf2polynomial(mdegree);
        for (int i = 0; i < mdegree; i++)
        {
            if (polynomial
                .vectormult(((gf2npolynomialfield)mfield).squaringmatrix[mdegree
                    - i - 1]))
            {
                result.setbit(i);

            }
        }
        polynomial = result;
    }

    /**
     * squares this gf2npolynomialelement by shifting left its bitstring and
     * reducing. this is supposed to be the slowest method. use squareprecalc or
     * squarematrix instead.
     *
     * @return <tt>this<sup>2</sup></tt> (newly created)
     * @see gf2npolynomialelement#squarematrix
     * @see gf2npolynomialelement#squareprecalc
     * @see gf2polynomial#squarethisbitwise
     */
    public gf2npolynomialelement squarebitwise()
    {
        gf2npolynomialelement result = new gf2npolynomialelement(this);
        result.squarethisbitwise();
        result.reducethis();
        return result;
    }

    /**
     * squares this gf2npolynomialelement by shifting left its bitstring and
     * reducing. this is supposed to be the slowest method. use squareprecalc or
     * squarematrix instead.
     *
     * @see gf2npolynomialelement#squarematrix
     * @see gf2npolynomialelement#squareprecalc
     * @see gf2polynomial#squarethisbitwise
     */
    public void squarethisbitwise()
    {
        polynomial.squarethisbitwise();
        reducethis();
    }

    /**
     * squares this gf2npolynomialelement by using precalculated values and
     * reducing. this is supposed to de fastest when using a trinomial or
     * pentanomial as field polynomial. use squarematrix when using a ordinary
     * polynomial as field polynomial.
     *
     * @return <tt>this<sup>2</sup></tt> (newly created)
     * @see gf2npolynomialelement#squarematrix
     * @see gf2polynomial#squarethisprecalc
     */
    public gf2npolynomialelement squareprecalc()
    {
        gf2npolynomialelement result = new gf2npolynomialelement(this);
        result.squarethisprecalc();
        result.reducethis();
        return result;
    }

    /**
     * squares this gf2npolynomialelement by using precalculated values and
     * reducing. this is supposed to de fastest when using a tri- or pentanomial
     * as fieldpolynomial. use squarematrix when using a ordinary polynomial as
     * fieldpolynomial.
     *
     * @see gf2npolynomialelement#squarematrix
     * @see gf2polynomial#squarethisprecalc
     */
    public void squarethisprecalc()
    {
        polynomial.squarethisprecalc();
        reducethis();
    }

    /**
     * calculates <i>this</i> to the power of <i>k</i> and returns the result
     * in a new gf2npolynomialelement.
     *
     * @param k the power
     * @return <i>this</i>^<i>k</i> in a new gf2npolynomialelement
     */
    public gf2npolynomialelement power(int k)
    {
        if (k == 1)
        {
            return new gf2npolynomialelement(this);
        }

        gf2npolynomialelement result = gf2npolynomialelement
            .one((gf2npolynomialfield)mfield);
        if (k == 0)
        {
            return result;
        }

        gf2npolynomialelement x = new gf2npolynomialelement(this);
        x.polynomial.expandn((x.mdegree << 1) + 32); // increase performance
        x.polynomial.reducen();

        for (int i = 0; i < mdegree; i++)
        {
            if ((k & (1 << i)) != 0)
            {
                result.multiplythisby(x);
            }
            x.square();
        }

        return result;
    }

    /**
     * compute the square root of this element and return the result in a new
     * {@link gf2npolynomialelement}.
     *
     * @return <tt>this<sup>1/2</sup></tt> (newly created)
     */
    public gf2nelement squareroot()
    {
        gf2npolynomialelement result = new gf2npolynomialelement(this);
        result.squarerootthis();
        return result;
    }

    /**
     * compute the square root of this element.
     */
    public void squarerootthis()
    {
        // increase performance
        polynomial.expandn((mdegree << 1) + 32);
        polynomial.reducen();
        for (int i = 0; i < mfield.getdegree() - 1; i++)
        {
            squarethis();
        }
    }

    /**
     * solves the quadratic equation <tt>z<sup>2</sup> + z = this</tt> if
     * such a solution exists. this method returns one of the two possible
     * solutions. the other solution is <tt>z + 1</tt>. use z.increase() to
     * compute this solution.
     *
     * @return a gf2npolynomialelement representing one z satisfying the
     *         equation <tt>z<sup>2</sup> + z = this</tt>
     * @throws nosolutionexception if no solution exists
     * @see "ieee 1363, annex a.4.7"
     */
    public gf2nelement solvequadraticequation()
        throws runtimeexception
    {
        if (iszero())
        {
            return zero((gf2npolynomialfield)mfield);
        }

        if ((mdegree & 1) == 1)
        {
            return halftrace();
        }

        // todo this can be sped-up by precomputation of p and w's
        gf2npolynomialelement z, w;
        do
        {
            // step 1.
            gf2npolynomialelement p = new gf2npolynomialelement(
                (gf2npolynomialfield)mfield, new random());
            // step 2.
            z = zero((gf2npolynomialfield)mfield);
            w = (gf2npolynomialelement)p.clone();
            // step 3.
            for (int i = 1; i < mdegree; i++)
            {
                // compute z = z^2 + w^2 * this
                // and w = w^2 + p
                z.squarethis();
                w.squarethis();
                z.addtothis(w.multiply(this));
                w.addtothis(p);
            }
        }
        while (w.iszero()); // step 4.

        if (!equals(z.square().add(z)))
        {
            throw new runtimeexception();
        }

        // step 5.
        return z;
    }

    /**
     * returns the trace of this gf2npolynomialelement.
     *
     * @return the trace of this gf2npolynomialelement
     */
    public int trace()
    {
        gf2npolynomialelement t = new gf2npolynomialelement(this);
        int i;

        for (i = 1; i < mdegree; i++)
        {
            t.squarethis();
            t.addtothis(this);
        }

        if (t.isone())
        {
            return 1;
        }
        return 0;
    }

    /**
     * returns the half-trace of this gf2npolynomialelement.
     *
     * @return a gf2npolynomialelement representing the half-trace of this
     *         gf2npolynomialelement.
     * @throws degreeisevenexception if the degree of this gf2npolynomialelement is even.
     */
    private gf2npolynomialelement halftrace()
        throws runtimeexception
    {
        if ((mdegree & 0x01) == 0)
        {
            throw new runtimeexception();
        }
        int i;
        gf2npolynomialelement h = new gf2npolynomialelement(this);

        for (i = 1; i <= ((mdegree - 1) >> 1); i++)
        {
            h.squarethis();
            h.squarethis();
            h.addtothis(this);
        }

        return h;
    }

    /**
     * reduces this gf2npolynomialelement modulo the field-polynomial.
     *
     * @see gf2polynomial#reducetrinomial
     * @see gf2polynomial#reducepentanomial
     */
    private void reducethis()
    {
        if (polynomial.getlength() > mdegree)
        { // really reduce ?
            if (((gf2npolynomialfield)mfield).istrinomial())
            { // fieldpolonomial
                // is trinomial
                int tc;
                try
                {
                    tc = ((gf2npolynomialfield)mfield).gettc();
                }
                catch (runtimeexception natexc)
                {
                    throw new runtimeexception(
                        "gf2npolynomialelement.reduce: the field"
                            + " polynomial is not a trinomial");
                }
                if (((mdegree - tc) <= 32) // do we have to use slow
                    // bitwise reduction ?
                    || (polynomial.getlength() > (mdegree << 1)))
                {
                    reducetrinomialbitwise(tc);
                    return;
                }
                polynomial.reducetrinomial(mdegree, tc);
                return;
            }
            else if (((gf2npolynomialfield)mfield).ispentanomial())
            { // fieldpolynomial
                // is
                // pentanomial
                int[] pc;
                try
                {
                    pc = ((gf2npolynomialfield)mfield).getpc();
                }
                catch (runtimeexception natexc)
                {
                    throw new runtimeexception(
                        "gf2npolynomialelement.reduce: the field"
                            + " polynomial is not a pentanomial");
                }
                if (((mdegree - pc[2]) <= 32) // do we have to use slow
                    // bitwise reduction ?
                    || (polynomial.getlength() > (mdegree << 1)))
                {
                    reducepentanomialbitwise(pc);
                    return;
                }
                polynomial.reducepentanomial(mdegree, pc);
                return;
            }
            else
            { // fieldpolynomial is something else
                polynomial = polynomial.remainder(mfield.getfieldpolynomial());
                polynomial.expandn(mdegree);
                return;
            }
        }
        if (polynomial.getlength() < mdegree)
        {
            polynomial.expandn(mdegree);
        }
    }

    /**
     * reduce this gf2npolynomialelement using the trinomial x^n + x^tc + 1 as
     * fieldpolynomial. the coefficients are reduced bit by bit.
     */
    private void reducetrinomialbitwise(int tc)
    {
        int i;
        int k = mdegree - tc;
        for (i = polynomial.getlength() - 1; i >= mdegree; i--)
        {
            if (polynomial.testbit(i))
            {

                polynomial.xorbit(i);
                polynomial.xorbit(i - k);
                polynomial.xorbit(i - mdegree);

            }
        }
        polynomial.reducen();
        polynomial.expandn(mdegree);
    }

    /**
     * reduce this gf2npolynomialelement using the pentanomial x^n + x^pc[2] +
     * x^pc[1] + x^pc[0] + 1 as fieldpolynomial. the coefficients are reduced
     * bit by bit.
     */
    private void reducepentanomialbitwise(int[] pc)
    {
        int i;
        int k = mdegree - pc[2];
        int l = mdegree - pc[1];
        int m = mdegree - pc[0];
        for (i = polynomial.getlength() - 1; i >= mdegree; i--)
        {
            if (polynomial.testbit(i))
            {
                polynomial.xorbit(i);
                polynomial.xorbit(i - k);
                polynomial.xorbit(i - l);
                polynomial.xorbit(i - m);
                polynomial.xorbit(i - mdegree);

            }
        }
        polynomial.reducen();
        polynomial.expandn(mdegree);
    }

    // /////////////////////////////////////////////////////////////////////
    // conversion
    // /////////////////////////////////////////////////////////////////////

    /**
     * returns a string representing this bitstrings value using hexadecimal
     * radix in msb-first order.
     *
     * @return a string representing this bitstrings value.
     */
    public string tostring()
    {
        return polynomial.tostring(16);
    }

    /**
     * returns a string representing this bitstrings value using hexadecimal or
     * binary radix in msb-first order.
     *
     * @param radix the radix to use (2 or 16, otherwise 2 is used)
     * @return a string representing this bitstrings value.
     */
    public string tostring(int radix)
    {
        return polynomial.tostring(radix);
    }

    /**
     * converts this gf2npolynomialelement to a byte[] according to 1363.
     *
     * @return a byte[] representing the value of this gf2npolynomialelement
     * @see "p1363 5.5.2 p22f bs2osp, fe2osp"
     */
    public byte[] tobytearray()
    {
        return polynomial.tobytearray();
    }

    /**
     * converts this gf2npolynomialelement to an integer according to 1363.
     *
     * @return a biginteger representing the value of this
     *         gf2npolynomialelement
     * @see "p1363 5.5.1 p22 bs2ip"
     */
    public biginteger toflexibigint()
    {
        return polynomial.toflexibigint();
    }

}
