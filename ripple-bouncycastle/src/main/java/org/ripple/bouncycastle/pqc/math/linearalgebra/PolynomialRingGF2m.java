package org.ripple.bouncycastle.pqc.math.linearalgebra;

/**
 * this class represents polynomial rings <tt>gf(2^m)[x]/p(x)</tt> for
 * <tt>m&lt<;32</tt>. if <tt>p(x)</tt> is irreducible, the polynomial ring
 * is in fact an extension field of <tt>gf(2^m)</tt>.
 */
public class polynomialringgf2m
{

    /**
     * the finite field this polynomial ring is defined over
     */
    private gf2mfield field;

    /**
     * the reduction polynomial
     */
    private polynomialgf2msmallm p;

    /**
     * the squaring matrix for this polynomial ring (given as the array of its
     * row vectors)
     */
    protected polynomialgf2msmallm[] sqmatrix;

    /**
     * the matrix for computing square roots in this polynomial ring (given as
     * the array of its row vectors). this matrix is computed as the inverse of
     * the squaring matrix.
     */
    protected polynomialgf2msmallm[] sqrootmatrix;

    /**
     * constructor.
     *
     * @param field the finite field
     * @param p     the reduction polynomial
     */
    public polynomialringgf2m(gf2mfield field, polynomialgf2msmallm p)
    {
        this.field = field;
        this.p = p;
        computesquaringmatrix();
        computesquarerootmatrix();
    }

    /**
     * @return the squaring matrix for this polynomial ring
     */
    public polynomialgf2msmallm[] getsquaringmatrix()
    {
        return sqmatrix;
    }

    /**
     * @return the matrix for computing square roots for this polynomial ring
     */
    public polynomialgf2msmallm[] getsquarerootmatrix()
    {
        return sqrootmatrix;
    }

    /**
     * compute the squaring matrix for this polynomial ring, using the base
     * field and the reduction polynomial.
     */
    private void computesquaringmatrix()
    {
        int numcolumns = p.getdegree();
        sqmatrix = new polynomialgf2msmallm[numcolumns];
        for (int i = 0; i < numcolumns >> 1; i++)
        {
            int[] monomcoeffs = new int[(i << 1) + 1];
            monomcoeffs[i << 1] = 1;
            sqmatrix[i] = new polynomialgf2msmallm(field, monomcoeffs);
        }
        for (int i = numcolumns >> 1; i < numcolumns; i++)
        {
            int[] monomcoeffs = new int[(i << 1) + 1];
            monomcoeffs[i << 1] = 1;
            polynomialgf2msmallm monomial = new polynomialgf2msmallm(field,
                monomcoeffs);
            sqmatrix[i] = monomial.mod(p);
        }
    }

    /**
     * compute the matrix for computing square roots in this polynomial ring by
     * inverting the squaring matrix.
     */
    private void computesquarerootmatrix()
    {
        int numcolumns = p.getdegree();

        // clone squaring matrix
        polynomialgf2msmallm[] tmpmatrix = new polynomialgf2msmallm[numcolumns];
        for (int i = numcolumns - 1; i >= 0; i--)
        {
            tmpmatrix[i] = new polynomialgf2msmallm(sqmatrix[i]);
        }

        // initialize square root matrix as unit matrix
        sqrootmatrix = new polynomialgf2msmallm[numcolumns];
        for (int i = numcolumns - 1; i >= 0; i--)
        {
            sqrootmatrix[i] = new polynomialgf2msmallm(field, i);
        }

        // simultaneously compute gaussian reduction of squaring matrix and unit
        // matrix
        for (int i = 0; i < numcolumns; i++)
        {
            // if diagonal element is zero
            if (tmpmatrix[i].getcoefficient(i) == 0)
            {
                boolean foundnonzero = false;
                // find a non-zero element in the same row
                for (int j = i + 1; j < numcolumns; j++)
                {
                    if (tmpmatrix[j].getcoefficient(i) != 0)
                    {
                        // found it, swap columns ...
                        foundnonzero = true;
                        swapcolumns(tmpmatrix, i, j);
                        swapcolumns(sqrootmatrix, i, j);
                        // ... and quit searching
                        j = numcolumns;
                        continue;
                    }
                }
                // if no non-zero element was found
                if (!foundnonzero)
                {
                    // the matrix is not invertible
                    throw new arithmeticexception(
                        "squaring matrix is not invertible.");
                }
            }

            // normalize i-th column
            int coef = tmpmatrix[i].getcoefficient(i);
            int invcoef = field.inverse(coef);
            tmpmatrix[i].multthiswithelement(invcoef);
            sqrootmatrix[i].multthiswithelement(invcoef);

            // normalize all other columns
            for (int j = 0; j < numcolumns; j++)
            {
                if (j != i)
                {
                    coef = tmpmatrix[j].getcoefficient(i);
                    if (coef != 0)
                    {
                        polynomialgf2msmallm tmpsqcolumn = tmpmatrix[i]
                            .multwithelement(coef);
                        polynomialgf2msmallm tmpinvcolumn = sqrootmatrix[i]
                            .multwithelement(coef);
                        tmpmatrix[j].addtothis(tmpsqcolumn);
                        sqrootmatrix[j].addtothis(tmpinvcolumn);
                    }
                }
            }
        }
    }

    private static void swapcolumns(polynomialgf2msmallm[] matrix, int first,
                                    int second)
    {
        polynomialgf2msmallm tmp = matrix[first];
        matrix[first] = matrix[second];
        matrix[second] = tmp;
    }

}
