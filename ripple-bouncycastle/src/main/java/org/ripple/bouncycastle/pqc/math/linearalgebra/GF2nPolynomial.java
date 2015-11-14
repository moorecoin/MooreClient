package org.ripple.bouncycastle.pqc.math.linearalgebra;


/**
 * this class implements polynomials over gf2nelements.
 *
 * @see gf2nelement
 */

public class gf2npolynomial
{

    private gf2nelement[] coeff; // keeps the coefficients of this polynomial

    private int size; // the size of this polynomial

    /**
     * creates a new polynomialgf2n of size <i>deg</i> and elem as
     * coefficients.
     *
     * @param deg  -
     *             the maximum degree + 1
     * @param elem -
     *             a gf2nelement
     */
    public gf2npolynomial(int deg, gf2nelement elem)
    {
        size = deg;
        coeff = new gf2nelement[size];
        for (int i = 0; i < size; i++)
        {
            coeff[i] = (gf2nelement)elem.clone();
        }
    }

    /**
     * creates a new polynomialgf2n of size <i>deg</i>.
     *
     * @param deg the maximum degree + 1
     */
    private gf2npolynomial(int deg)
    {
        size = deg;
        coeff = new gf2nelement[size];
    }

    /**
     * creates a new polynomialgf2n by cloning the given polynomialgf2n <i>a</i>.
     *
     * @param a the polynomialgf2n to clone
     */
    public gf2npolynomial(gf2npolynomial a)
    {
        int i;
        coeff = new gf2nelement[a.size];
        size = a.size;
        for (i = 0; i < size; i++)
        {
            coeff[i] = (gf2nelement)a.coeff[i].clone();
        }
    }

    /**
     * creates a new polynomialgf2n from the given bitstring <i>polynomial</i>
     * over the gf2nfield <i>b1</i>.
     *
     * @param polynomial the bitstring to use
     * @param b1         the field
     */
    public gf2npolynomial(gf2polynomial polynomial, gf2nfield b1)
    {
        size = b1.getdegree() + 1;
        coeff = new gf2nelement[size];
        int i;
        if (b1 instanceof gf2nonbfield)
        {
            for (i = 0; i < size; i++)
            {
                if (polynomial.testbit(i))
                {
                    coeff[i] = gf2nonbelement.one((gf2nonbfield)b1);
                }
                else
                {
                    coeff[i] = gf2nonbelement.zero((gf2nonbfield)b1);
                }
            }
        }
        else if (b1 instanceof gf2npolynomialfield)
        {
            for (i = 0; i < size; i++)
            {
                if (polynomial.testbit(i))
                {
                    coeff[i] = gf2npolynomialelement
                        .one((gf2npolynomialfield)b1);
                }
                else
                {
                    coeff[i] = gf2npolynomialelement
                        .zero((gf2npolynomialfield)b1);
                }
            }
        }
        else
        {
            throw new illegalargumentexception(
                "polynomialgf2n(bitstring, gf2nfield): b1 must be "
                    + "an instance of gf2nonbfield or gf2npolynomialfield!");
        }
    }

    public final void assignzerotoelements()
    {
        int i;
        for (i = 0; i < size; i++)
        {
            coeff[i].assignzero();
        }
    }

    /**
     * returns the size (=maximum degree + 1) of this polynomialgf2n. this is
     * not the degree, use getdegree instead.
     *
     * @return the size (=maximum degree + 1) of this polynomialgf2n.
     */
    public final int size()
    {
        return size;
    }

    /**
     * returns the degree of this polynomialgf2n.
     *
     * @return the degree of this polynomialgf2n.
     */
    public final int getdegree()
    {
        int i;
        for (i = size - 1; i >= 0; i--)
        {
            if (!coeff[i].iszero())
            {
                return i;
            }
        }
        return -1;
    }

    /**
     * enlarges the size of this polynomialgf2n to <i>k</i> + 1.
     *
     * @param k the new maximum degree
     */
    public final void enlarge(int k)
    {
        if (k <= size)
        {
            return;
        }
        int i;
        gf2nelement[] res = new gf2nelement[k];
        system.arraycopy(coeff, 0, res, 0, size);
        gf2nfield f = coeff[0].getfield();
        if (coeff[0] instanceof gf2npolynomialelement)
        {
            for (i = size; i < k; i++)
            {
                res[i] = gf2npolynomialelement.zero((gf2npolynomialfield)f);
            }
        }
        else if (coeff[0] instanceof gf2nonbelement)
        {
            for (i = size; i < k; i++)
            {
                res[i] = gf2nonbelement.zero((gf2nonbfield)f);
            }
        }
        size = k;
        coeff = res;
    }

    public final void shrink()
    {
        int i = size - 1;
        while (coeff[i].iszero() && (i > 0))
        {
            i--;
        }
        i++;
        if (i < size)
        {
            gf2nelement[] res = new gf2nelement[i];
            system.arraycopy(coeff, 0, res, 0, i);
            coeff = res;
            size = i;
        }
    }

    /**
     * sets the coefficient at <i>index</i> to <i>elem</i>.
     *
     * @param index the index
     * @param elem  the gf2nelement to store as coefficient <i>index</i>
     */
    public final void set(int index, gf2nelement elem)
    {
        if (!(elem instanceof gf2npolynomialelement)
            && !(elem instanceof gf2nonbelement))
        {
            throw new illegalargumentexception(
                "polynomialgf2n.set f must be an "
                    + "instance of either gf2npolynomialelement or gf2nonbelement!");
        }
        coeff[index] = (gf2nelement)elem.clone();
    }

    /**
     * returns the coefficient at <i>index</i>.
     *
     * @param index the index
     * @return the gf2nelement stored as coefficient <i>index</i>
     */
    public final gf2nelement at(int index)
    {
        return coeff[index];
    }

    /**
     * returns true if all coefficients equal zero.
     *
     * @return true if all coefficients equal zero.
     */
    public final boolean iszero()
    {
        int i;
        for (i = 0; i < size; i++)
        {
            if (coeff[i] != null)
            {
                if (!coeff[i].iszero())
                {
                    return false;
                }
            }
        }
        return true;
    }

    public final boolean equals(object other)
    {
        if (other == null || !(other instanceof gf2npolynomial))
        {
            return false;
        }

        gf2npolynomial otherpol = (gf2npolynomial)other;

        if (getdegree() != otherpol.getdegree())
        {
            return false;
        }
        int i;
        for (i = 0; i < size; i++)
        {
            if (!coeff[i].equals(otherpol.coeff[i]))
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
        return getdegree() + coeff.hashcode();
    }

    /**
     * adds the polynomialgf2n <tt>b</tt> to <tt>this</tt> and returns the
     * result in a new <tt>polynomialgf2n</tt>.
     *
     * @param b -
     *          the <tt>polynomialgf2n</tt> to add
     * @return <tt>this + b</tt>
     * @throws differentfieldsexception if <tt>this</tt> and <tt>b</tt> are not defined over
     * the same field.
     */
    public final gf2npolynomial add(gf2npolynomial b)
        throws runtimeexception
    {
        gf2npolynomial result;
        if (size() >= b.size())
        {
            result = new gf2npolynomial(size());
            int i;
            for (i = 0; i < b.size(); i++)
            {
                result.coeff[i] = (gf2nelement)coeff[i].add(b.coeff[i]);
            }
            for (; i < size(); i++)
            {
                result.coeff[i] = coeff[i];
            }
        }
        else
        {
            result = new gf2npolynomial(b.size());
            int i;
            for (i = 0; i < size(); i++)
            {
                result.coeff[i] = (gf2nelement)coeff[i].add(b.coeff[i]);
            }
            for (; i < b.size(); i++)
            {
                result.coeff[i] = b.coeff[i];
            }
        }
        return result;
    }

    /**
     * multiplies the scalar <i>s</i> to each coefficient of this
     * polynomialgf2n and returns the result in a new polynomialgf2n.
     *
     * @param s the scalar to multiply
     * @return <i>this</i> x <i>s</i>
     * @throws differentfieldsexception if <tt>this</tt> and <tt>s</tt> are not defined over
     * the same field.
     */
    public final gf2npolynomial scalarmultiply(gf2nelement s)
        throws runtimeexception
    {
        gf2npolynomial result = new gf2npolynomial(size());
        int i;
        for (i = 0; i < size(); i++)
        {
            result.coeff[i] = (gf2nelement)coeff[i].multiply(s); // result[i]
            // =
            // a[i]*s
        }
        return result;
    }

    /**
     * multiplies <i>this</i> by <i>b</i> and returns the result in a new
     * polynomialgf2n.
     *
     * @param b the polynomialgf2n to multiply
     * @return <i>this</i> * <i>b</i>
     * @throws differentfieldsexception if <tt>this</tt> and <tt>b</tt> are not defined over
     * the same field.
     */
    public final gf2npolynomial multiply(gf2npolynomial b)
        throws runtimeexception
    {
        int i, j;
        int adegree = size();
        int bdegree = b.size();
        if (adegree != bdegree)
        {
            throw new illegalargumentexception(
                "polynomialgf2n.multiply: this and b must "
                    + "have the same size!");
        }
        gf2npolynomial result = new gf2npolynomial((adegree << 1) - 1);
        for (i = 0; i < size(); i++)
        {
            for (j = 0; j < b.size(); j++)
            {
                if (result.coeff[i + j] == null)
                {
                    result.coeff[i + j] = (gf2nelement)coeff[i]
                        .multiply(b.coeff[j]);
                }
                else
                {
                    result.coeff[i + j] = (gf2nelement)result.coeff[i + j]
                        .add(coeff[i].multiply(b.coeff[j]));
                }
            }
        }
        return result;
    }

    /**
     * multiplies <i>this</i> by <i>b</i>, reduces the result by <i>g</i> and
     * returns it in a new polynomialgf2n.
     *
     * @param b the polynomialgf2n to multiply
     * @param g the modul
     * @return <i>this</i> * <i>b</i> mod <i>g</i>
     * @throws differentfieldsexception if <tt>this</tt>, <tt>b</tt> and <tt>g</tt> are
     * not all defined over the same field.
     */
    public final gf2npolynomial multiplyandreduce(gf2npolynomial b,
                                                  gf2npolynomial g)
        throws runtimeexception,
        arithmeticexception
    {
        return multiply(b).reduce(g);
    }

    /**
     * reduces <i>this</i> by <i>g</i> and returns the result in a new
     * polynomialgf2n.
     *
     * @param g -
     *          the modulus
     * @return <i>this</i> % <i>g</i>
     * @throws differentfieldsexception if <tt>this</tt> and <tt>g</tt> are not defined over
     * the same field.
     */
    public final gf2npolynomial reduce(gf2npolynomial g)
        throws runtimeexception, arithmeticexception
    {
        return remainder(g); // return this % g
    }

    /**
     * shifts left <i>this</i> by <i>amount</i> and stores the result in
     * <i>this</i> polynomialgf2n.
     *
     * @param amount the amount to shift the coefficients
     */
    public final void shiftthisleft(int amount)
    {
        if (amount > 0)
        {
            int i;
            int oldsize = size;
            gf2nfield f = coeff[0].getfield();
            enlarge(size + amount);
            for (i = oldsize - 1; i >= 0; i--)
            {
                coeff[i + amount] = coeff[i];
            }
            if (coeff[0] instanceof gf2npolynomialelement)
            {
                for (i = amount - 1; i >= 0; i--)
                {
                    coeff[i] = gf2npolynomialelement
                        .zero((gf2npolynomialfield)f);
                }
            }
            else if (coeff[0] instanceof gf2nonbelement)
            {
                for (i = amount - 1; i >= 0; i--)
                {
                    coeff[i] = gf2nonbelement.zero((gf2nonbfield)f);
                }
            }
        }
    }

    public final gf2npolynomial shiftleft(int amount)
    {
        if (amount <= 0)
        {
            return new gf2npolynomial(this);
        }
        gf2npolynomial result = new gf2npolynomial(size + amount, coeff[0]);
        result.assignzerotoelements();
        for (int i = 0; i < size; i++)
        {
            result.coeff[i + amount] = coeff[i];
        }
        return result;
    }

    /**
     * divides <i>this</i> by <i>b</i> and stores the result in a new
     * polynomialgf2n[2], quotient in result[0] and remainder in result[1].
     *
     * @param b the divisor
     * @return the quotient and remainder of <i>this</i> / <i>b</i>
     * @throws differentfieldsexception if <tt>this</tt> and <tt>b</tt> are not defined over
     * the same field.
     */
    public final gf2npolynomial[] divide(gf2npolynomial b)
        throws runtimeexception, arithmeticexception
    {
        gf2npolynomial[] result = new gf2npolynomial[2];
        gf2npolynomial a = new gf2npolynomial(this);
        a.shrink();
        gf2npolynomial shift;
        gf2nelement factor;
        int bdegree = b.getdegree();
        gf2nelement inv = (gf2nelement)b.coeff[bdegree].invert();
        if (a.getdegree() < bdegree)
        {
            result[0] = new gf2npolynomial(this);
            result[0].assignzerotoelements();
            result[0].shrink();
            result[1] = new gf2npolynomial(this);
            result[1].shrink();
            return result;
        }
        result[0] = new gf2npolynomial(this);
        result[0].assignzerotoelements();
        int i = a.getdegree() - bdegree;
        while (i >= 0)
        {
            factor = (gf2nelement)a.coeff[a.getdegree()].multiply(inv);
            shift = b.scalarmultiply(factor);
            shift.shiftthisleft(i);
            a = a.add(shift);
            a.shrink();
            result[0].coeff[i] = (gf2nelement)factor.clone();
            i = a.getdegree() - bdegree;
        }
        result[1] = a;
        result[0].shrink();
        return result;
    }

    /**
     * divides <i>this</i> by <i>b</i> and stores the remainder in a new
     * polynomialgf2n.
     *
     * @param b the divisor
     * @return the remainder <i>this</i> % <i>b</i>
     * @throws differentfieldsexception if <tt>this</tt> and <tt>b</tt> are not defined over
     * the same field.
     */
    public final gf2npolynomial remainder(gf2npolynomial b)
        throws runtimeexception, arithmeticexception
    {
        gf2npolynomial[] result = new gf2npolynomial[2];
        result = divide(b);
        return result[1];
    }

    /**
     * divides <i>this</i> by <i>b</i> and stores the quotient in a new
     * polynomialgf2n.
     *
     * @param b the divisor
     * @return the quotient <i>this</i> / <i>b</i>
     * @throws differentfieldsexception if <tt>this</tt> and <tt>b</tt> are not defined over
     * the same field.
     */
    public final gf2npolynomial quotient(gf2npolynomial b)
        throws runtimeexception, arithmeticexception
    {
        gf2npolynomial[] result = new gf2npolynomial[2];
        result = divide(b);
        return result[0];
    }

    /**
     * computes the greatest common divisor of <i>this</i> and <i>g</i> and
     * returns the result in a new polynomialgf2n.
     *
     * @param g -
     *          a gf2npolynomial
     * @return gcd(<i>this</i>, <i>g</i>)
     * @throws differentfieldsexception if the coefficients of <i>this</i> and <i>g</i> use
     * different fields
     * @throws arithmeticexception if coefficients are zero.
     */
    public final gf2npolynomial gcd(gf2npolynomial g)
        throws runtimeexception, arithmeticexception
    {
        gf2npolynomial a = new gf2npolynomial(this);
        gf2npolynomial b = new gf2npolynomial(g);
        a.shrink();
        b.shrink();
        gf2npolynomial c;
        gf2npolynomial result;
        gf2nelement alpha;
        while (!b.iszero())
        {
            c = a.remainder(b);
            a = b;
            b = c;
        }
        alpha = a.coeff[a.getdegree()];
        result = a.scalarmultiply((gf2nelement)alpha.invert());
        return result;
    }

}
