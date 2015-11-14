package org.ripple.bouncycastle.pqc.math.linearalgebra;

import java.security.securerandom;

/**
 * this class describes decoding operations of an irreducible binary goppa code.
 * a check matrix h of the goppa code and an irreducible goppa polynomial are
 * used the operations are worked over a finite field gf(2^m)
 *
 * @see gf2mfield
 * @see polynomialgf2msmallm
 */
public final class goppacode
{

    /**
     * default constructor (private).
     */
    private goppacode()
    {
        // empty
    }

    /**
     * this class is a container for two instances of {@link gf2matrix} and one
     * instance of {@link permutation}. it is used to hold the systematic form
     * <tt>s*h*p = (id|m)</tt> of the check matrix <tt>h</tt> as returned by
     * {@link goppacode#computesystematicform(gf2matrix, securerandom)}.
     *
     * @see gf2matrix
     * @see permutation
     */
    public static class mamape
    {

        private gf2matrix s, h;

        private permutation p;

        /**
         * construct a new {@link mamape} container with the given parameters.
         *
         * @param s the first matrix
         * @param h the second matrix
         * @param p the permutation
         */
        public mamape(gf2matrix s, gf2matrix h, permutation p)
        {
            this.s = s;
            this.h = h;
            this.p = p;
        }

        /**
         * @return the first matrix
         */
        public gf2matrix getfirstmatrix()
        {
            return s;
        }

        /**
         * @return the second matrix
         */
        public gf2matrix getsecondmatrix()
        {
            return h;
        }

        /**
         * @return the permutation
         */
        public permutation getpermutation()
        {
            return p;
        }
    }

    /**
     * this class is a container for an instance of {@link gf2matrix} and one
     * int[]. it is used to hold a generator matrix and the set of indices such
     * that the submatrix of the generator matrix consisting of the specified
     * columns is the identity.
     *
     * @see gf2matrix
     * @see permutation
     */
    public static class matrixset
    {

        private gf2matrix g;

        private int[] setj;

        /**
         * construct a new {@link matrixset} container with the given
         * parameters.
         *
         * @param g    the generator matrix
         * @param setj the set of indices such that the submatrix of the
         *             generator matrix consisting of the specified columns
         *             is the identity
         */
        public matrixset(gf2matrix g, int[] setj)
        {
            this.g = g;
            this.setj = setj;
        }

        /**
         * @return the generator matrix
         */
        public gf2matrix getg()
        {
            return g;
        }

        /**
         * @return the set of indices such that the submatrix of the generator
         *         matrix consisting of the specified columns is the identity
         */
        public int[] getsetj()
        {
            return setj;
        }
    }

    /**
     * construct the check matrix of a goppa code in canonical form from the
     * irreducible goppa polynomial over the finite field
     * <tt>gf(2<sup>m</sup>)</tt>.
     *
     * @param field the finite field
     * @param gp    the irreducible goppa polynomial
     */
    public static gf2matrix createcanonicalcheckmatrix(gf2mfield field,
                                                       polynomialgf2msmallm gp)
    {
        int m = field.getdegree();
        int n = 1 << m;
        int t = gp.getdegree();

        /* create matrix h over gf(2^m) */

        int[][] harray = new int[t][n];

        // create matrix yz
        int[][] yz = new int[t][n];
        for (int j = 0; j < n; j++)
        {
            // here j is used as index and as element of field gf(2^m)
            yz[0][j] = field.inverse(gp.evaluateat(j));
        }

        for (int i = 1; i < t; i++)
        {
            for (int j = 0; j < n; j++)
            {
                // here j is used as index and as element of field gf(2^m)
                yz[i][j] = field.mult(yz[i - 1][j], j);
            }
        }

        // create matrix h = xyz
        for (int i = 0; i < t; i++)
        {
            for (int j = 0; j < n; j++)
            {
                for (int k = 0; k <= i; k++)
                {
                    harray[i][j] = field.add(harray[i][j], field.mult(yz[k][j],
                        gp.getcoefficient(t + k - i)));
                }
            }
        }

        /* convert to matrix over gf(2) */

        int[][] result = new int[t * m][(n + 31) >>> 5];

        for (int j = 0; j < n; j++)
        {
            int q = j >>> 5;
            int r = 1 << (j & 0x1f);
            for (int i = 0; i < t; i++)
            {
                int e = harray[i][j];
                for (int u = 0; u < m; u++)
                {
                    int b = (e >>> u) & 1;
                    if (b != 0)
                    {
                        int ind = (i + 1) * m - u - 1;
                        result[ind][q] ^= r;
                    }
                }
            }
        }

        return new gf2matrix(n, result);
    }

    /**
     * given a check matrix <tt>h</tt>, compute matrices <tt>s</tt>,
     * <tt>m</tt>, and a random permutation <tt>p</tt> such that
     * <tt>s*h*p = (id|m)</tt>. return <tt>s^-1</tt>, <tt>m</tt>, and
     * <tt>p</tt> as {@link mamape}. the matrix <tt>(id | m)</tt> is called
     * the systematic form of h.
     *
     * @param h  the check matrix
     * @param sr a source of randomness
     * @return the tuple <tt>(s^-1, m, p)</tt>
     */
    public static mamape computesystematicform(gf2matrix h, securerandom sr)
    {
        int n = h.getnumcolumns();
        gf2matrix hp, sinv;
        gf2matrix s = null;
        permutation p;
        boolean found = false;

        do
        {
            p = new permutation(n, sr);
            hp = (gf2matrix)h.rightmultiply(p);
            sinv = hp.getleftsubmatrix();
            try
            {
                found = true;
                s = (gf2matrix)sinv.computeinverse();
            }
            catch (arithmeticexception ae)
            {
                found = false;
            }
        }
        while (!found);

        gf2matrix shp = (gf2matrix)s.rightmultiply(hp);
        gf2matrix m = shp.getrightsubmatrix();

        return new mamape(sinv, m, p);
    }

    /**
     * find an error vector <tt>e</tt> over <tt>gf(2)</tt> from an input
     * syndrome <tt>s</tt> over <tt>gf(2<sup>m</sup>)</tt>.
     *
     * @param syndvec      the syndrome
     * @param field        the finite field
     * @param gp           the irreducible goppa polynomial
     * @param sqrootmatrix the matrix for computing square roots in
     *                     <tt>(gf(2<sup>m</sup>))<sup>t</sup></tt>
     * @return the error vector
     */
    public static gf2vector syndromedecode(gf2vector syndvec, gf2mfield field,
                                           polynomialgf2msmallm gp, polynomialgf2msmallm[] sqrootmatrix)
    {

        int n = 1 << field.getdegree();

        // the error vector
        gf2vector errors = new gf2vector(n);

        // if the syndrome vector is zero, the error vector is also zero
        if (!syndvec.iszero())
        {
            // convert syndrome vector to polynomial over gf(2^m)
            polynomialgf2msmallm syndrome = new polynomialgf2msmallm(syndvec
                .toextensionfieldvector(field));

            // compute t = syndrome^-1 mod gp
            polynomialgf2msmallm t = syndrome.modinverse(gp);

            // compute tau = sqroot(t + x) mod gp
            polynomialgf2msmallm tau = t.addmonomial(1);
            tau = tau.modsquarerootmatrix(sqrootmatrix);

            // compute polynomials a and b satisfying a + b*tau = 0 mod gp
            polynomialgf2msmallm[] ab = tau.modpolynomialtofracton(gp);

            // compute the polynomial a^2 + x*b^2
            polynomialgf2msmallm a2 = ab[0].multiply(ab[0]);
            polynomialgf2msmallm b2 = ab[1].multiply(ab[1]);
            polynomialgf2msmallm xb2 = b2.multwithmonomial(1);
            polynomialgf2msmallm a2plusxb2 = a2.add(xb2);

            // normalize a^2 + x*b^2 to obtain the error locator polynomial
            int headcoeff = a2plusxb2.getheadcoefficient();
            int invheadcoeff = field.inverse(headcoeff);
            polynomialgf2msmallm elp = a2plusxb2.multwithelement(invheadcoeff);

            // for all elements i of gf(2^m)
            for (int i = 0; i < n; i++)
            {
                // evaluate the error locator polynomial at i
                int z = elp.evaluateat(i);
                // if polynomial evaluates to zero
                if (z == 0)
                {
                    // set the i-th coefficient of the error vector
                    errors.setbit(i);
                }
            }
        }

        return errors;
    }

}
