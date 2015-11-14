package org.ripple.bouncycastle.pqc.math.linearalgebra;


import java.util.vector;


/**
 * this abstract class defines the finite field <i>gf(2<sup>n</sup>)</i>. it
 * holds the extension degree <i>n</i>, the characteristic, the irreducible
 * fieldpolynomial and conversion matrices. gf2nfield is implemented by the
 * classes gf2npolynomialfield and gf2nonbfield.
 *
 * @see gf2nonbfield
 * @see gf2npolynomialfield
 */
public abstract class gf2nfield
{

    /**
     * the degree of this field
     */
    protected int mdegree;

    /**
     * the irreducible fieldpolynomial stored in normal order (also for onb)
     */
    protected gf2polynomial fieldpolynomial;

    /**
     * holds a list of gf2nfields to which elements have been converted and thus
     * a cob-matrix exists
     */
    protected vector fields;

    /**
     * the cob matrices
     */
    protected vector matrices;

    /**
     * returns the degree <i>n</i> of this field.
     *
     * @return the degree <i>n</i> of this field
     */
    public final int getdegree()
    {
        return mdegree;
    }

    /**
     * returns the fieldpolynomial as a new bitstring.
     *
     * @return a copy of the fieldpolynomial as a new bitstring
     */
    public final gf2polynomial getfieldpolynomial()
    {
        if (fieldpolynomial == null)
        {
            computefieldpolynomial();
        }
        return new gf2polynomial(fieldpolynomial);
    }

    /**
     * decides whether the given object <tt>other</tt> is the same as this
     * field.
     *
     * @param other another object
     * @return (this == other)
     */
    public final boolean equals(object other)
    {
        if (other == null || !(other instanceof gf2nfield))
        {
            return false;
        }

        gf2nfield otherfield = (gf2nfield)other;

        if (otherfield.mdegree != mdegree)
        {
            return false;
        }
        if (!fieldpolynomial.equals(otherfield.fieldpolynomial))
        {
            return false;
        }
        if ((this instanceof gf2npolynomialfield)
            && !(otherfield instanceof gf2npolynomialfield))
        {
            return false;
        }
        if ((this instanceof gf2nonbfield)
            && !(otherfield instanceof gf2nonbfield))
        {
            return false;
        }
        return true;
    }

    /**
     * @return the hash code of this field
     */
    public int hashcode()
    {
        return mdegree + fieldpolynomial.hashcode();
    }

    /**
     * computes a random root from the given irreducible fieldpolynomial
     * according to ieee 1363 algorithm a.5.6. this cal take very long for big
     * degrees.
     *
     * @param b0fieldpolynomial the fieldpolynomial if the other basis as a bitstring
     * @return a random root of bofieldpolynomial in representation according to
     *         this field
     * @see "p1363 a.5.6, p103f"
     */
    protected abstract gf2nelement getrandomroot(gf2polynomial b0fieldpolynomial);

    /**
     * computes the change-of-basis matrix for basis conversion according to
     * 1363. the result is stored in the lists fields and matrices.
     *
     * @param b1 the gf2nfield to convert to
     * @see "p1363 a.7.3, p111ff"
     */
    protected abstract void computecobmatrix(gf2nfield b1);

    /**
     * computes the fieldpolynomial. this can take a long time for big degrees.
     */
    protected abstract void computefieldpolynomial();

    /**
     * inverts the given matrix represented as bitstrings.
     *
     * @param matrix the matrix to invert as a bitstring[]
     * @return matrix^(-1)
     */
    protected final gf2polynomial[] invertmatrix(gf2polynomial[] matrix)
    {
        gf2polynomial[] a = new gf2polynomial[matrix.length];
        gf2polynomial[] inv = new gf2polynomial[matrix.length];
        gf2polynomial dummy;
        int i, j;
        // initialize a as a copy of matrix and inv as e(inheitsmatrix)
        for (i = 0; i < mdegree; i++)
        {
            try
            {
                a[i] = new gf2polynomial(matrix[i]);
                inv[i] = new gf2polynomial(mdegree);
                inv[i].setbit(mdegree - 1 - i);
            }
            catch (runtimeexception bdneexc)
            {
                bdneexc.printstacktrace();
            }
        }
        // construct triangle matrix so that for each a[i] the first i bits are
        // zero
        for (i = 0; i < mdegree - 1; i++)
        {
            // find column where bit i is set
            j = i;
            while ((j < mdegree) && !a[j].testbit(mdegree - 1 - i))
            {
                j++;
            }
            if (j >= mdegree)
            {
                throw new runtimeexception(
                    "gf2nfield.invertmatrix: matrix cannot be inverted!");
            }
            if (i != j)
            { // swap a[i]/a[j] and inv[i]/inv[j]
                dummy = a[i];
                a[i] = a[j];
                a[j] = dummy;
                dummy = inv[i];
                inv[i] = inv[j];
                inv[j] = dummy;
            }
            for (j = i + 1; j < mdegree; j++)
            { // add column i to all columns>i
                // having their i-th bit set
                if (a[j].testbit(mdegree - 1 - i))
                {
                    a[j].addtothis(a[i]);
                    inv[j].addtothis(inv[i]);
                }
            }
        }
        // construct einheitsmatrix from a
        for (i = mdegree - 1; i > 0; i--)
        {
            for (j = i - 1; j >= 0; j--)
            { // eliminate the i-th bit in all
                // columns < i
                if (a[j].testbit(mdegree - 1 - i))
                {
                    a[j].addtothis(a[i]);
                    inv[j].addtothis(inv[i]);
                }
            }
        }
        return inv;
    }

    /**
     * converts the given element in representation according to this field to a
     * new element in representation according to b1 using the change-of-basis
     * matrix calculated by computecobmatrix.
     *
     * @param elem  the gf2nelement to convert
     * @param basis the basis to convert <tt>elem</tt> to
     * @return <tt>elem</tt> converted to a new element representation
     *         according to <tt>basis</tt>
     * @throws differentfieldsexception if <tt>elem</tt> cannot be converted according to
     * <tt>basis</tt>.
     * @see gf2nfield#computecobmatrix
     * @see gf2nfield#getrandomroot
     * @see gf2npolynomial
     * @see "p1363 a.7 p109ff"
     */
    public final gf2nelement convert(gf2nelement elem, gf2nfield basis)
        throws runtimeexception
    {
        if (basis == this)
        {
            return (gf2nelement)elem.clone();
        }
        if (fieldpolynomial.equals(basis.fieldpolynomial))
        {
            return (gf2nelement)elem.clone();
        }
        if (mdegree != basis.mdegree)
        {
            throw new runtimeexception("gf2nfield.convert: b1 has a"
                + " different degree and thus cannot be coverted to!");
        }

        int i;
        gf2polynomial[] cobmatrix;
        i = fields.indexof(basis);
        if (i == -1)
        {
            computecobmatrix(basis);
            i = fields.indexof(basis);
        }
        cobmatrix = (gf2polynomial[])matrices.elementat(i);

        gf2nelement elemcopy = (gf2nelement)elem.clone();
        if (elemcopy instanceof gf2nonbelement)
        {
            // remember: onb treats its bits in reverse order
            ((gf2nonbelement)elemcopy).reverseorder();
        }
        gf2polynomial bs = new gf2polynomial(mdegree, elemcopy.toflexibigint());
        bs.expandn(mdegree);
        gf2polynomial result = new gf2polynomial(mdegree);
        for (i = 0; i < mdegree; i++)
        {
            if (bs.vectormult(cobmatrix[i]))
            {
                result.setbit(mdegree - 1 - i);
            }
        }
        if (basis instanceof gf2npolynomialfield)
        {
            return new gf2npolynomialelement((gf2npolynomialfield)basis,
                result);
        }
        else if (basis instanceof gf2nonbfield)
        {
            gf2nonbelement res = new gf2nonbelement((gf2nonbfield)basis,
                result.toflexibigint());
            // todo remember: onb treats its bits in reverse order !!!
            res.reverseorder();
            return res;
        }
        else
        {
            throw new runtimeexception(
                "gf2nfield.convert: b1 must be an instance of "
                    + "gf2npolynomialfield or gf2nonbfield!");
        }

    }

}
