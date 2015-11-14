package org.ripple.bouncycastle.pqc.math.linearalgebra;


import java.util.random;
import java.util.vector;


/**
 * this class implements the abstract class <tt>gf2nfield</tt> for polynomial
 * representation. it computes the field polynomial and the squaring matrix.
 * gf2nfield is used by gf2npolynomialelement which implements the elements of
 * this field.
 *
 * @see gf2nfield
 * @see gf2npolynomialelement
 */
public class gf2npolynomialfield
    extends gf2nfield
{

    /**
     * matrix used for fast squaring
     */
    gf2polynomial[] squaringmatrix;

    // field polynomial is a trinomial
    private boolean istrinomial = false;

    // field polynomial is a pentanomial
    private boolean ispentanomial = false;

    // middle coefficient of the field polynomial in case it is a trinomial
    private int tc;

    // middle 3 coefficients of the field polynomial in case it is a pentanomial
    private int[] pc = new int[3];

    /**
     * constructs an instance of the finite field with 2<sup>deg</sup>
     * elements and characteristic 2.
     *
     * @param deg the extention degree of this field
     */
    public gf2npolynomialfield(int deg)
    {
        if (deg < 3)
        {
            throw new illegalargumentexception("k must be at least 3");
        }
        mdegree = deg;
        computefieldpolynomial();
        computesquaringmatrix();
        fields = new vector();
        matrices = new vector();
    }

    /**
     * constructs an instance of the finite field with 2<sup>deg</sup>
     * elements and characteristic 2.
     *
     * @param deg  the degree of this field
     * @param file true if you want to read the field polynomial from the
     *             file false if you want to use a random fielpolynomial
     *             (this can take very long for huge degrees)
     */
    public gf2npolynomialfield(int deg, boolean file)
    {
        if (deg < 3)
        {
            throw new illegalargumentexception("k must be at least 3");
        }
        mdegree = deg;
        if (file)
        {
            computefieldpolynomial();
        }
        else
        {
            computefieldpolynomial2();
        }
        computesquaringmatrix();
        fields = new vector();
        matrices = new vector();
    }

    /**
     * creates a new gf2nfield of degree <i>i</i> and uses the given
     * <i>polynomial</i> as field polynomial. the <i>polynomial</i> is checked
     * whether it is irreducible. this can take some time if <i>i</i> is huge!
     *
     * @param deg        degree of the gf2nfield
     * @param polynomial the field polynomial to use
     * @throws polynomialisnotirreducibleexception if the given polynomial is not irreducible in gf(2^<i>i</i>)
     */
    public gf2npolynomialfield(int deg, gf2polynomial polynomial)
        throws runtimeexception
    {
        if (deg < 3)
        {
            throw new illegalargumentexception("degree must be at least 3");
        }
        if (polynomial.getlength() != deg + 1)
        {
            throw new runtimeexception();
        }
        if (!polynomial.isirreducible())
        {
            throw new runtimeexception();
        }
        mdegree = deg;
        // fieldpolynomial = new bitstring(polynomial);
        fieldpolynomial = polynomial;
        computesquaringmatrix();
        int k = 2; // check if the polynomial is a trinomial or pentanomial
        for (int j = 1; j < fieldpolynomial.getlength() - 1; j++)
        {
            if (fieldpolynomial.testbit(j))
            {
                k++;
                if (k == 3)
                {
                    tc = j;
                }
                if (k <= 5)
                {
                    pc[k - 3] = j;
                }
            }
        }
        if (k == 3)
        {
            istrinomial = true;
        }
        if (k == 5)
        {
            ispentanomial = true;
        }
        fields = new vector();
        matrices = new vector();
    }

    /**
     * returns true if the field polynomial is a trinomial. the coefficient can
     * be retrieved using gettc().
     *
     * @return true if the field polynomial is a trinomial
     */
    public boolean istrinomial()
    {
        return istrinomial;
    }

    /**
     * returns true if the field polynomial is a pentanomial. the coefficients
     * can be retrieved using getpc().
     *
     * @return true if the field polynomial is a pentanomial
     */
    public boolean ispentanomial()
    {
        return ispentanomial;
    }

    /**
     * returns the degree of the middle coefficient of the used field trinomial
     * (x^n + x^(gettc()) + 1).
     *
     * @return the middle coefficient of the used field trinomial
     * @throws gfexception if the field polynomial is not a trinomial
     */
    public int gettc()
        throws runtimeexception
    {
        if (!istrinomial)
        {
            throw new runtimeexception();
        }
        return tc;
    }

    /**
     * returns the degree of the middle coefficients of the used field
     * pentanomial (x^n + x^(getpc()[2]) + x^(getpc()[1]) + x^(getpc()[0]) + 1).
     *
     * @return the middle coefficients of the used field pentanomial
     * @throws gfexception if the field polynomial is not a pentanomial
     */
    public int[] getpc()
        throws runtimeexception
    {
        if (!ispentanomial)
        {
            throw new runtimeexception();
        }
        int[] result = new int[3];
        system.arraycopy(pc, 0, result, 0, 3);
        return result;
    }

    /**
     * return row vector i of the squaring matrix.
     *
     * @param i the index of the row vector to return
     * @return a copy of squaringmatrix[i]
     * @see gf2npolynomialelement#squarematrix
     */
    public gf2polynomial getsquaringvector(int i)
    {
        return new gf2polynomial(squaringmatrix[i]);
    }

    /**
     * compute a random root of the given gf2polynomial.
     *
     * @param polynomial the polynomial
     * @return a random root of <tt>polynomial</tt>
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
                u = new gf2npolynomialelement(this, new random());
                ut = new gf2npolynomial(2, gf2npolynomialelement.zero(this));
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
                "gf2npolynomialfield.computecobmatrix: b1 has a different "
                    + "degree and thus cannot be coverted to!");
        }
        if (b1 instanceof gf2nonbfield)
        {
            // speedup (calculation is done in polynomialelements instead of
            // onb)
            b1.computecobmatrix(this);
            return;
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

        // build gamma matrix by multiplying by u
        if (u instanceof gf2nonbelement)
        {
            gamma = new gf2nonbelement[mdegree];
            gamma[mdegree - 1] = gf2nonbelement.one((gf2nonbfield)b1);
        }
        else
        {
            gamma = new gf2npolynomialelement[mdegree];
            gamma[mdegree - 1] = gf2npolynomialelement
                .one((gf2npolynomialfield)b1);
        }
        gamma[mdegree - 2] = u;
        for (i = mdegree - 3; i >= 0; i--)
        {
            gamma[i] = (gf2nelement)gamma[i + 1].multiply(u);
        }
        if (b1 instanceof gf2nonbfield)
        {
            // convert horizontal gamma matrix by vertical bitstrings
            for (i = 0; i < mdegree; i++)
            {
                for (j = 0; j < mdegree; j++)
                {
                    // todo remember: onb treats its bits in reverse order !!!
                    if (gamma[i].testbit(mdegree - j - 1))
                    {
                        cobmatrix[mdegree - j - 1].setbit(mdegree - i - 1);
                    }
                }
            }
        }
        else
        {
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
        }

        // store field and matrix for further use
        fields.addelement(b1);
        matrices.addelement(cobmatrix);
        // store field and inverse matrix for further use in b1
        b1.fields.addelement(this);
        b1.matrices.addelement(invertmatrix(cobmatrix));
    }

    /**
     * computes a new squaring matrix used for fast squaring.
     *
     * @see gf2npolynomialelement#square
     */
    private void computesquaringmatrix()
    {
        gf2polynomial[] d = new gf2polynomial[mdegree - 1];
        int i, j;
        squaringmatrix = new gf2polynomial[mdegree];
        for (i = 0; i < squaringmatrix.length; i++)
        {
            squaringmatrix[i] = new gf2polynomial(mdegree, "zero");
        }

        for (i = 0; i < mdegree - 1; i++)
        {
            d[i] = new gf2polynomial(1, "one").shiftleft(mdegree + i)
                .remainder(fieldpolynomial);
        }
        for (i = 1; i <= math.abs(mdegree >> 1); i++)
        {
            for (j = 1; j <= mdegree; j++)
            {
                if (d[mdegree - (i << 1)].testbit(mdegree - j))
                {
                    squaringmatrix[j - 1].setbit(mdegree - i);
                }
            }
        }
        for (i = math.abs(mdegree >> 1) + 1; i <= mdegree; i++)
        {
            squaringmatrix[(i << 1) - mdegree - 1].setbit(mdegree - i);
        }

    }

    /**
     * computes the field polynomial. this can take a long time for big degrees.
     */
    protected void computefieldpolynomial()
    {
        if (testtrinomials())
        {
            return;
        }
        if (testpentanomials())
        {
            return;
        }
        testrandom();
    }

    /**
     * computes the field polynomial. this can take a long time for big degrees.
     */
    protected void computefieldpolynomial2()
    {
        if (testtrinomials())
        {
            return;
        }
        if (testpentanomials())
        {
            return;
        }
        testrandom();
    }

    /**
     * tests all trinomials of degree (n+1) until a irreducible is found and
     * stores the result in <i>field polynomial</i>. returns false if no
     * irreducible trinomial exists in gf(2^n). this can take very long for huge
     * degrees.
     *
     * @return true if an irreducible trinomial is found
     */
    private boolean testtrinomials()
    {
        int i, l;
        boolean done = false;
        l = 0;

        fieldpolynomial = new gf2polynomial(mdegree + 1);
        fieldpolynomial.setbit(0);
        fieldpolynomial.setbit(mdegree);
        for (i = 1; (i < mdegree) && !done; i++)
        {
            fieldpolynomial.setbit(i);
            done = fieldpolynomial.isirreducible();
            l++;
            if (done)
            {
                istrinomial = true;
                tc = i;
                return done;
            }
            fieldpolynomial.resetbit(i);
            done = fieldpolynomial.isirreducible();
        }

        return done;
    }

    /**
     * tests all pentanomials of degree (n+1) until a irreducible is found and
     * stores the result in <i>field polynomial</i>. returns false if no
     * irreducible pentanomial exists in gf(2^n). this can take very long for
     * huge degrees.
     *
     * @return true if an irreducible pentanomial is found
     */
    private boolean testpentanomials()
    {
        int i, j, k, l;
        boolean done = false;
        l = 0;

        fieldpolynomial = new gf2polynomial(mdegree + 1);
        fieldpolynomial.setbit(0);
        fieldpolynomial.setbit(mdegree);
        for (i = 1; (i <= (mdegree - 3)) && !done; i++)
        {
            fieldpolynomial.setbit(i);
            for (j = i + 1; (j <= (mdegree - 2)) && !done; j++)
            {
                fieldpolynomial.setbit(j);
                for (k = j + 1; (k <= (mdegree - 1)) && !done; k++)
                {
                    fieldpolynomial.setbit(k);
                    if (((mdegree & 1) != 0) | ((i & 1) != 0) | ((j & 1) != 0)
                        | ((k & 1) != 0))
                    {
                        done = fieldpolynomial.isirreducible();
                        l++;
                        if (done)
                        {
                            ispentanomial = true;
                            pc[0] = i;
                            pc[1] = j;
                            pc[2] = k;
                            return done;
                        }
                    }
                    fieldpolynomial.resetbit(k);
                }
                fieldpolynomial.resetbit(j);
            }
            fieldpolynomial.resetbit(i);
        }

        return done;
    }

    /**
     * tests random polynomials of degree (n+1) until an irreducible is found
     * and stores the result in <i>field polynomial</i>. this can take very
     * long for huge degrees.
     *
     * @return true
     */
    private boolean testrandom()
    {
        int l;
        boolean done = false;

        fieldpolynomial = new gf2polynomial(mdegree + 1);
        l = 0;
        while (!done)
        {
            l++;
            fieldpolynomial.randomize();
            fieldpolynomial.setbit(mdegree);
            fieldpolynomial.setbit(0);
            if (fieldpolynomial.isirreducible())
            {
                done = true;
                return done;
            }
        }

        return done;
    }

}
