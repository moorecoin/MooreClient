package org.ripple.bouncycastle.pqc.math.linearalgebra;


import java.util.random;
import java.util.vector;


/**
 * this class implements the abstract class <tt>gf2nfield</tt> for onb
 * representation. it computes the fieldpolynomial, multiplication matrix and
 * one of its roots monbroot, (see for example <a
 * href=http://www2.certicom.com/ecc/intro.htm>certicoms whitepapers</a>).
 * gf2nfield is used by gf2nonbelement which implements the elements of this
 * field.
 *
 * @see gf2nfield
 * @see gf2nonbelement
 */
public class gf2nonbfield
    extends gf2nfield
{

    // ///////////////////////////////////////////////////////////////////
    // hashtable for irreducible normal polynomials //
    // ///////////////////////////////////////////////////////////////////

    // i*5 + 0 i*5 + 1 i*5 + 2 i*5 + 3 i*5 + 4
    /*
     * private static int[][] mnb = {{0, 0, 0}, {0, 0, 0}, {1, 0, 0}, {1, 0, 0},
     * {1, 0, 0}, // i = 0 {2, 0, 0}, {1, 0, 0}, {1, 0, 0}, {4, 3, 1}, {1, 0,
     * 0}, // i = 1 {3, 0, 0}, {2, 0, 0}, {3, 0, 0}, {4, 3, 1}, {5, 0, 0}, // i =
     * 2 {1, 0, 0}, {5, 3, 1}, {3, 0, 0}, {3, 0, 0}, {5, 2, 1}, // i = 3 {3, 0,
     * 0}, {2, 0, 0}, {1, 0, 0}, {5, 0, 0}, {4, 3, 1}, // i = 4 {3, 0, 0}, {4,
     * 3, 1}, {5, 2, 1}, {1, 0, 0}, {2, 0, 0}, // i = 5 {1, 0, 0}, {3, 0, 0},
     * {7, 3, 2}, {10, 0, 0}, {7, 0, 0}, // i = 6 {2, 0, 0}, {9, 0, 0}, {6, 4,
     * 1}, {6, 5, 1}, {4, 0, 0}, // i = 7 {5, 4, 3}, {3, 0, 0}, {7, 0, 0}, {6,
     * 4, 3}, {5, 0, 0}, // i = 8 {4, 3, 1}, {1, 0, 0}, {5, 0, 0}, {5, 3, 2},
     * {9, 0, 0}, // i = 9 {4, 3, 2}, {6, 3, 1}, {3, 0, 0}, {6, 2, 1}, {9, 0,
     * 0}, // i = 10 {7, 0, 0}, {7, 4, 2}, {4, 0, 0}, {19, 0, 0}, {7, 4, 2}, //
     * i = 11 {1, 0, 0}, {5, 2, 1}, {29, 0, 0}, {1, 0, 0}, {4, 3, 1}, // i = 12
     * {18, 0, 0}, {3, 0, 0}, {5, 2, 1}, {9, 0, 0}, {6, 5, 2}, // i = 13 {5, 3,
     * 1}, {6, 0, 0}, {10, 9, 3}, {25, 0, 0}, {35, 0, 0}, // i = 14 {6, 3, 1},
     * {21, 0, 0}, {6, 5, 2}, {6, 5, 3}, {9, 0, 0}, // i = 15 {9, 4, 2}, {4, 0,
     * 0}, {8, 3, 1}, {7, 4, 2}, {5, 0, 0}, // i = 16 {8, 2, 1}, {21, 0, 0},
     * {13, 0, 0}, {7, 6, 2}, {38, 0, 0}, // i = 17 {27, 0, 0}, {8, 5, 1}, {21,
     * 0, 0}, {2, 0, 0}, {21, 0, 0}, // i = 18 {11, 0, 0}, {10, 9, 6}, {6, 0,
     * 0}, {11, 0, 0}, {6, 3, 1}, // i = 19 {15, 0, 0}, {7, 6, 1}, {29, 0, 0},
     * {9, 0, 0}, {4, 3, 1}, // i = 20 {4, 0, 0}, {15, 0, 0}, {9, 7, 4}, {17, 0,
     * 0}, {5, 4, 2}, // i = 21 {33, 0, 0}, {10, 0, 0}, {5, 4, 3}, {9, 0, 0},
     * {5, 3, 2}, // i = 22 {8, 7, 5}, {4, 2, 1}, {5, 2, 1}, {33, 0, 0}, {8, 0,
     * 0}, // i = 23 {4, 3, 1}, {18, 0, 0}, {6, 2, 1}, {2, 0, 0}, {19, 0, 0}, //
     * i = 24 {7, 6, 5}, {21, 0, 0}, {1, 0, 0}, {7, 2, 1}, {5, 0, 0}, // i = 25
     * {3, 0, 0}, {8, 3, 2}, {17, 0, 0}, {9, 8, 2}, {57, 0, 0}, // i = 26 {11,
     * 0, 0}, {5, 3, 2}, {21, 0, 0}, {8, 7, 1}, {8, 5, 3}, // i = 27 {15, 0, 0},
     * {10, 4, 1}, {21, 0, 0}, {5, 3, 2}, {7, 4, 2}, // i = 28 {52, 0, 0}, {71,
     * 0, 0}, {14, 0, 0}, {27, 0, 0}, {10, 9, 7}, // i = 29 {53, 0, 0}, {3, 0,
     * 0}, {6, 3, 2}, {1, 0, 0}, {15, 0, 0}, // i = 30 {62, 0, 0}, {9, 0, 0},
     * {6, 5, 2}, {8, 6, 5}, {31, 0, 0}, // i = 31 {5, 3, 2}, {18, 0, 0 }, {27,
     * 0, 0}, {7, 6, 3}, {10, 8, 7}, // i = 32 {9, 8, 3}, {37, 0, 0}, {6, 0, 0},
     * {15, 3, 2}, {34, 0, 0}, // i = 33 {11, 0, 0}, {6, 5, 2}, {1, 0, 0}, {8,
     * 5, 2}, {13, 0, 0}, // i = 34 {6, 0, 0}, {11, 3, 2}, {8, 0, 0}, {31, 0,
     * 0}, {4, 2, 1}, // i = 35 {3, 0, 0}, {7, 6, 1}, {81, 0, 0}, {56, 0, 0},
     * {9, 8, 7}, // i = 36 {24, 0, 0}, {11, 0, 0}, {7, 6, 5}, {6, 5, 2}, {6, 5,
     * 2}, // i = 37 {8, 7, 6}, {9, 0, 0}, {7, 2, 1}, {15, 0, 0}, {87, 0, 0}, //
     * i = 38 {8, 3, 2}, {3, 0, 0}, {9, 4, 2}, {9, 0, 0}, {34, 0, 0}, // i = 39
     * {5, 3, 2}, {14, 0, 0}, {55, 0, 0}, {8, 7, 1}, {27, 0, 0}, // i = 40 {9,
     * 5, 2}, {10, 9, 5}, {43, 0, 0}, {8, 6, 2}, {6, 0, 0}, // i = 41 {7, 0, 0},
     * {11, 10, 8}, {105, 0, 0}, {6, 5, 2}, {73, 0, 0}}; // i = 42
     */
    // /////////////////////////////////////////////////////////////////////
    // member variables
    // /////////////////////////////////////////////////////////////////////
    private static final int maxlong = 64;

    /**
     * holds the length of the array-representation of degree mdegree.
     */
    private int mlength;

    /**
     * holds the number of relevant bits in monbpol[mlength-1].
     */
    private int mbit;

    /**
     * holds the type of monb
     */
    private int mtype;

    /**
     * holds the multiplication matrix
     */
    int[][] mmult;

    // /////////////////////////////////////////////////////////////////////
    // constructors
    // /////////////////////////////////////////////////////////////////////

    /**
     * constructs an instance of the finite field with 2<sup>deg</sup>
     * elements and characteristic 2.
     *
     * @param deg -
     *            the extention degree of this field
     * @throws nosuchbasisexception if an onb-implementation other than type 1 or type 2 is
     * requested.
     */
    public gf2nonbfield(int deg)
        throws runtimeexception
    {
        if (deg < 3)
        {
            throw new illegalargumentexception("k must be at least 3");
        }

        mdegree = deg;
        mlength = mdegree / maxlong;
        mbit = mdegree & (maxlong - 1);
        if (mbit == 0)
        {
            mbit = maxlong;
        }
        else
        {
            mlength++;
        }

        computetype();

        // only onb-implementations for type 1 and type 2
        //
        if (mtype < 3)
        {
            mmult = new int[mdegree][2];
            for (int i = 0; i < mdegree; i++)
            {
                mmult[i][0] = -1;
                mmult[i][1] = -1;
            }
            computemultmatrix();
        }
        else
        {
            throw new runtimeexception("\nthe type of this field is "
                + mtype);
        }
        computefieldpolynomial();
        fields = new vector();
        matrices = new vector();
    }

    // /////////////////////////////////////////////////////////////////////
    // access
    // /////////////////////////////////////////////////////////////////////

    int getonblength()
    {
        return mlength;
    }

    int getonbbit()
    {
        return mbit;
    }

    // /////////////////////////////////////////////////////////////////////
    // arithmetic
    // /////////////////////////////////////////////////////////////////////

    /**
     * computes a random root of the given polynomial.
     *
     * @param polynomial a polynomial
     * @return a random root of the polynomial
     * @see "p1363 a.5.6, p103f"
     */
    protected gf2nelement getrandomroot(gf2polynomial polynomial)
    {
        // we are in b1!!!
        gf2npolynomial c;
        gf2npolynomial ut;
        gf2nelement u;
        gf2npolynomial h;
        int hdegree;
        // 1. set g(t) <- f(t)
        gf2npolynomial g = new gf2npolynomial(polynomial, this);
        int gdegree = g.getdegree();
        int i;

        // 2. while deg(g) > 1
        while (gdegree > 1)
        {
            do
            {
                // 2.1 choose random u (element of) gf(2^m)
                u = new gf2nonbelement(this, new random());
                ut = new gf2npolynomial(2, gf2nonbelement.zero(this));
                // 2.2 set c(t) <- ut
                ut.set(1, u);
                c = new gf2npolynomial(ut);
                // 2.3 for i from 1 to m-1 do
                for (i = 1; i <= mdegree - 1; i++)
                {
                    // 2.3.1 c(t) <- (c(t)^2 + ut) mod g(t)
                    c = c.multiplyandreduce(c, g);
                    c = c.add(ut);
                }
                // 2.4 set h(t) <- gcd(c(t), g(t))
                h = c.gcd(g);
                // 2.5 if h(t) is constant or deg(g) = deg(h) then go to
                // step 2.1
                hdegree = h.getdegree();
                gdegree = g.getdegree();
            }
            while ((hdegree == 0) || (hdegree == gdegree));
            // 2.6 if 2deg(h) > deg(g) then set g(t) <- g(t)/h(t) ...
            if ((hdegree << 1) > gdegree)
            {
                g = g.quotient(h);
            }
            else
            {
                // ... else g(t) <- h(t)
                g = new gf2npolynomial(h);
            }
            gdegree = g.getdegree();
        }
        // 3. output g(0)
        return g.at(0);

    }

    /**
     * computes the change-of-basis matrix for basis conversion according to
     * 1363. the result is stored in the lists fields and matrices.
     *
     * @param b1 the gf2nfield to convert to
     * @see "p1363 a.7.3, p111ff"
     */
    protected void computecobmatrix(gf2nfield b1)
    {
        // we are in b0 here!
        if (mdegree != b1.mdegree)
        {
            throw new illegalargumentexception(
                "gf2nfield.computecobmatrix: b1 has a "
                    + "different degree and thus cannot be coverted to!");
        }
        int i, j;
        gf2nelement[] gamma;
        gf2nelement u;
        gf2polynomial[] cobmatrix = new gf2polynomial[mdegree];
        for (i = 0; i < mdegree; i++)
        {
            cobmatrix[i] = new gf2polynomial(mdegree);
        }

        // find random root
        do
        {
            // u is in representation according to b1
            u = b1.getrandomroot(fieldpolynomial);
        }
        while (u.iszero());

        gamma = new gf2npolynomialelement[mdegree];
        // build gamma matrix by squaring
        gamma[0] = (gf2nelement)u.clone();
        for (i = 1; i < mdegree; i++)
        {
            gamma[i] = gamma[i - 1].square();
        }
        // convert horizontal gamma matrix by vertical bitstrings
        for (i = 0; i < mdegree; i++)
        {
            for (j = 0; j < mdegree; j++)
            {
                if (gamma[i].testbit(j))
                {
                    cobmatrix[mdegree - j - 1].setbit(mdegree - i - 1);
                }
            }
        }

        fields.addelement(b1);
        matrices.addelement(cobmatrix);
        b1.fields.addelement(this);
        b1.matrices.addelement(invertmatrix(cobmatrix));
    }

    /**
     * computes the field polynomial for a onb according to ieee 1363 a.7.2
     * (p110f).
     *
     * @see "p1363 a.7.2, p110f"
     */
    protected void computefieldpolynomial()
    {
        if (mtype == 1)
        {
            fieldpolynomial = new gf2polynomial(mdegree + 1, "all");
        }
        else if (mtype == 2)
        {
            // 1. q = 1
            gf2polynomial q = new gf2polynomial(mdegree + 1, "one");
            // 2. p = t+1
            gf2polynomial p = new gf2polynomial(mdegree + 1, "x");
            p.addtothis(q);
            gf2polynomial r;
            int i;
            // 3. for i = 1 to (m-1) do
            for (i = 1; i < mdegree; i++)
            {
                // r <- q
                r = q;
                // q <- p
                q = p;
                // p = tq+r
                p = q.shiftleft();
                p.addtothis(r);
            }
            fieldpolynomial = p;
        }
    }

    /**
     * compute the inverse of a matrix <tt>a</tt>.
     *
     * @param a the matrix
     * @return <tt>a<sup>-1</sup></tt>
     */
    int[][] invmatrix(int[][] a)
    {

        int[][] a = new int[mdegree][mdegree];
        a = a;
        int[][] inv = new int[mdegree][mdegree];

        for (int i = 0; i < mdegree; i++)
        {
            inv[i][i] = 1;
        }

        for (int i = 0; i < mdegree; i++)
        {
            for (int j = i; j < mdegree; j++)
            {
                a[mdegree - 1 - i][j] = a[i][i];
            }
        }
        return null;
    }

    private void computetype()
        throws runtimeexception
    {
        if ((mdegree & 7) == 0)
        {
            throw new runtimeexception(
                "the extension degree is divisible by 8!");
        }
        // checking for the type
        int s = 0;
        int k = 0;
        mtype = 1;
        for (int d = 0; d != 1; mtype++)
        {
            s = mtype * mdegree + 1;
            if (integerfunctions.isprime(s))
            {
                k = integerfunctions.order(2, s);
                d = integerfunctions.gcd(mtype * mdegree / k, mdegree);
            }
        }
        mtype--;
        if (mtype == 1)
        {
            s = (mdegree << 1) + 1;
            if (integerfunctions.isprime(s))
            {
                k = integerfunctions.order(2, s);
                int d = integerfunctions.gcd((mdegree << 1) / k, mdegree);
                if (d == 1)
                {
                    mtype++;
                }
            }
        }
    }

    private void computemultmatrix()
    {

        if ((mtype & 7) != 0)
        {
            int p = mtype * mdegree + 1;

            // compute sequence f[1] ... f[p-1] via a.3.7. of 1363.
            // f[0] will not be filled!
            //
            int[] f = new int[p];

            int u;
            if (mtype == 1)
            {
                u = 1;
            }
            else if (mtype == 2)
            {
                u = p - 1;
            }
            else
            {
                u = elementoforder(mtype, p);
            }

            int w = 1;
            int n;
            for (int j = 0; j < mtype; j++)
            {
                n = w;

                for (int i = 0; i < mdegree; i++)
                {
                    f[n] = i;
                    n = (n << 1) % p;
                    if (n < 0)
                    {
                        n += p;
                    }
                }
                w = u * w % p;
                if (w < 0)
                {
                    w += p;
                }
            }

            // building the matrix (mdegree * 2)
            //
            if (mtype == 1)
            {
                for (int k = 1; k < p - 1; k++)
                {
                    if (mmult[f[k + 1]][0] == -1)
                    {
                        mmult[f[k + 1]][0] = f[p - k];
                    }
                    else
                    {
                        mmult[f[k + 1]][1] = f[p - k];
                    }
                }

                int m_2 = mdegree >> 1;
                for (int k = 1; k <= m_2; k++)
                {

                    if (mmult[k - 1][0] == -1)
                    {
                        mmult[k - 1][0] = m_2 + k - 1;
                    }
                    else
                    {
                        mmult[k - 1][1] = m_2 + k - 1;
                    }

                    if (mmult[m_2 + k - 1][0] == -1)
                    {
                        mmult[m_2 + k - 1][0] = k - 1;
                    }
                    else
                    {
                        mmult[m_2 + k - 1][1] = k - 1;
                    }
                }
            }
            else if (mtype == 2)
            {
                for (int k = 1; k < p - 1; k++)
                {
                    if (mmult[f[k + 1]][0] == -1)
                    {
                        mmult[f[k + 1]][0] = f[p - k];
                    }
                    else
                    {
                        mmult[f[k + 1]][1] = f[p - k];
                    }
                }
            }
            else
            {
                throw new runtimeexception("only type 1 or type 2 implemented");
            }
        }
        else
        {
            throw new runtimeexception("bisher nur fuer gausssche normalbasen"
                + " implementiert");
        }
    }

    private int elementoforder(int k, int p)
    {
        random random = new random();
        int m = 0;
        while (m == 0)
        {
            m = random.nextint();
            m %= p - 1;
            if (m < 0)
            {
                m += p - 1;
            }
        }

        int l = integerfunctions.order(m, p);

        while (l % k != 0 || l == 0)
        {
            while (m == 0)
            {
                m = random.nextint();
                m %= p - 1;
                if (m < 0)
                {
                    m += p - 1;
                }
            }
            l = integerfunctions.order(m, p);
        }
        int r = m;

        l = k / l;

        for (int i = 2; i <= l; i++)
        {
            r *= m;
        }

        return r;
    }

}
