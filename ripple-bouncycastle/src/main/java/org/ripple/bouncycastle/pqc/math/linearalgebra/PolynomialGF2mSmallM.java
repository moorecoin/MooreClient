package org.ripple.bouncycastle.pqc.math.linearalgebra;

import java.security.securerandom;

/**
 * this class describes operations with polynomials from the ring r =
 * gf(2^m)[x], where 2 <= m <=31.
 *
 * @see gf2mfield
 * @see polynomialringgf2m
 */
public class polynomialgf2msmallm
{

    /**
     * the finite field gf(2^m)
     */
    private gf2mfield field;

    /**
     * the degree of this polynomial
     */
    private int degree;

    /**
     * for the polynomial representation the map f: r->z*,
     * <tt>poly(x) -> [coef_0, coef_1, ...]</tt> is used, where
     * <tt>coef_i</tt> is the <tt>i</tt>th coefficient of the polynomial
     * represented as int (see {@link gf2mfield}). the polynomials are stored
     * as int arrays.
     */
    private int[] coefficients;

    /*
      * some types of polynomials
      */

    /**
     * constant used for polynomial construction (see constructor
     * {@link #polynomialgf2msmallm(gf2mfield, int, char, securerandom)}).
     */
    public static final char random_irreducible_polynomial = 'i';

    /**
     * construct the zero polynomial over the finite field gf(2^m).
     *
     * @param field the finite field gf(2^m)
     */
    public polynomialgf2msmallm(gf2mfield field)
    {
        this.field = field;
        degree = -1;
        coefficients = new int[1];
    }

    /**
     * construct a polynomial over the finite field gf(2^m).
     *
     * @param field            the finite field gf(2^m)
     * @param deg              degree of polynomial
     * @param typeofpolynomial type of polynomial
     * @param sr               prng
     */
    public polynomialgf2msmallm(gf2mfield field, int deg,
                                char typeofpolynomial, securerandom sr)
    {
        this.field = field;

        switch (typeofpolynomial)
        {
        case polynomialgf2msmallm.random_irreducible_polynomial:
            coefficients = createrandomirreduciblepolynomial(deg, sr);
            break;
        default:
            throw new illegalargumentexception(" error: type "
                + typeofpolynomial
                + " is not defined for gf2smallmpolynomial");
        }
        computedegree();
    }

    /**
     * create an irreducible polynomial with the given degree over the field
     * <tt>gf(2^m)</tt>.
     *
     * @param deg polynomial degree
     * @param sr  source of randomness
     * @return the generated irreducible polynomial
     */
    private int[] createrandomirreduciblepolynomial(int deg, securerandom sr)
    {
        int[] rescoeff = new int[deg + 1];
        rescoeff[deg] = 1;
        rescoeff[0] = field.getrandomnonzeroelement(sr);
        for (int i = 1; i < deg; i++)
        {
            rescoeff[i] = field.getrandomelement(sr);
        }
        while (!isirreducible(rescoeff))
        {
            int n = randutils.nextint(sr, deg);
            if (n == 0)
            {
                rescoeff[0] = field.getrandomnonzeroelement(sr);
            }
            else
            {
                rescoeff[n] = field.getrandomelement(sr);
            }
        }
        return rescoeff;
    }

    /**
     * construct a monomial of the given degree over the finite field gf(2^m).
     *
     * @param field  the finite field gf(2^m)
     * @param degree the degree of the monomial
     */
    public polynomialgf2msmallm(gf2mfield field, int degree)
    {
        this.field = field;
        this.degree = degree;
        coefficients = new int[degree + 1];
        coefficients[degree] = 1;
    }

    /**
     * construct the polynomial over the given finite field gf(2^m) from the
     * given coefficient vector.
     *
     * @param field  finite field gf2m
     * @param coeffs the coefficient vector
     */
    public polynomialgf2msmallm(gf2mfield field, int[] coeffs)
    {
        this.field = field;
        coefficients = normalform(coeffs);
        computedegree();
    }

    /**
     * create a polynomial over the finite field gf(2^m).
     *
     * @param field the finite field gf(2^m)
     * @param enc   byte[] polynomial in byte array form
     */
    public polynomialgf2msmallm(gf2mfield field, byte[] enc)
    {
        this.field = field;

        // decodes polynomial
        int d = 8;
        int count = 1;
        while (field.getdegree() > d)
        {
            count++;
            d += 8;
        }

        if ((enc.length % count) != 0)
        {
            throw new illegalargumentexception(
                " error: byte array is not encoded polynomial over given finite field gf2m");
        }

        coefficients = new int[enc.length / count];
        count = 0;
        for (int i = 0; i < coefficients.length; i++)
        {
            for (int j = 0; j < d; j += 8)
            {
                coefficients[i] ^= (enc[count++] & 0x000000ff) << j;
            }
            if (!this.field.iselementofthisfield(coefficients[i]))
            {
                throw new illegalargumentexception(
                    " error: byte array is not encoded polynomial over given finite field gf2m");
            }
        }
        // if hc = 0 for non-zero polynomial, returns error
        if ((coefficients.length != 1)
            && (coefficients[coefficients.length - 1] == 0))
        {
            throw new illegalargumentexception(
                " error: byte array is not encoded polynomial over given finite field gf2m");
        }
        computedegree();
    }

    /**
     * copy constructor.
     *
     * @param other another {@link polynomialgf2msmallm}
     */
    public polynomialgf2msmallm(polynomialgf2msmallm other)
    {
        // field needs not to be cloned since it is immutable
        field = other.field;
        degree = other.degree;
        coefficients = intutils.clone(other.coefficients);
    }

    /**
     * create a polynomial over the finite field gf(2^m) out of the given
     * coefficient vector. the finite field is also obtained from the
     * {@link gf2mvector}.
     *
     * @param vect the coefficient vector
     */
    public polynomialgf2msmallm(gf2mvector vect)
    {
        this(vect.getfield(), vect.getintarrayform());
    }

    /*
      * ------------------------
      */

    /**
     * return the degree of this polynomial
     *
     * @return int degree of this polynomial if this is zero polynomial return
     *         -1
     */
    public int getdegree()
    {
        int d = coefficients.length - 1;
        if (coefficients[d] == 0)
        {
            return -1;
        }
        return d;
    }

    /**
     * @return the head coefficient of this polynomial
     */
    public int getheadcoefficient()
    {
        if (degree == -1)
        {
            return 0;
        }
        return coefficients[degree];
    }

    /**
     * return the head coefficient of a polynomial.
     *
     * @param a the polynomial
     * @return the head coefficient of <tt>a</tt>
     */
    private static int headcoefficient(int[] a)
    {
        int degree = computedegree(a);
        if (degree == -1)
        {
            return 0;
        }
        return a[degree];
    }

    /**
     * return the coefficient with the given index.
     *
     * @param index the index
     * @return the coefficient with the given index
     */
    public int getcoefficient(int index)
    {
        if ((index < 0) || (index > degree))
        {
            return 0;
        }
        return coefficients[index];
    }

    /**
     * returns encoded polynomial, i.e., this polynomial in byte array form
     *
     * @return the encoded polynomial
     */
    public byte[] getencoded()
    {
        int d = 8;
        int count = 1;
        while (field.getdegree() > d)
        {
            count++;
            d += 8;
        }

        byte[] res = new byte[coefficients.length * count];
        count = 0;
        for (int i = 0; i < coefficients.length; i++)
        {
            for (int j = 0; j < d; j += 8)
            {
                res[count++] = (byte)(coefficients[i] >>> j);
            }
        }

        return res;
    }

    /**
     * evaluate this polynomial <tt>p</tt> at a value <tt>e</tt> (in
     * <tt>gf(2^m)</tt>) with the horner scheme.
     *
     * @param e the element of the finite field gf(2^m)
     * @return <tt>this(e)</tt>
     */
    public int evaluateat(int e)
    {
        int result = coefficients[degree];
        for (int i = degree - 1; i >= 0; i--)
        {
            result = field.mult(result, e) ^ coefficients[i];
        }
        return result;
    }

    /**
     * compute the sum of this polynomial and the given polynomial.
     *
     * @param addend the addend
     * @return <tt>this + a</tt> (newly created)
     */
    public polynomialgf2msmallm add(polynomialgf2msmallm addend)
    {
        int[] resultcoeff = add(coefficients, addend.coefficients);
        return new polynomialgf2msmallm(field, resultcoeff);
    }

    /**
     * add the given polynomial to this polynomial (overwrite this).
     *
     * @param addend the addend
     */
    public void addtothis(polynomialgf2msmallm addend)
    {
        coefficients = add(coefficients, addend.coefficients);
        computedegree();
    }

    /**
     * compute the sum of two polynomials a and b over the finite field
     * <tt>gf(2^m)</tt>.
     *
     * @param a the first polynomial
     * @param b the second polynomial
     * @return a + b
     */
    private int[] add(int[] a, int[] b)
    {
        int[] result, addend;
        if (a.length < b.length)
        {
            result = new int[b.length];
            system.arraycopy(b, 0, result, 0, b.length);
            addend = a;
        }
        else
        {
            result = new int[a.length];
            system.arraycopy(a, 0, result, 0, a.length);
            addend = b;
        }

        for (int i = addend.length - 1; i >= 0; i--)
        {
            result[i] = field.add(result[i], addend[i]);
        }

        return result;
    }

    /**
     * compute the sum of this polynomial and the monomial of the given degree.
     *
     * @param degree the degree of the monomial
     * @return <tt>this + x^k</tt>
     */
    public polynomialgf2msmallm addmonomial(int degree)
    {
        int[] monomial = new int[degree + 1];
        monomial[degree] = 1;
        int[] resultcoeff = add(coefficients, monomial);
        return new polynomialgf2msmallm(field, resultcoeff);
    }

    /**
     * compute the product of this polynomial with an element from gf(2^m).
     *
     * @param element an element of the finite field gf(2^m)
     * @return <tt>this * element</tt> (newly created)
     * @throws arithmeticexception if <tt>element</tt> is not an element of the finite
     * field this polynomial is defined over.
     */
    public polynomialgf2msmallm multwithelement(int element)
    {
        if (!field.iselementofthisfield(element))
        {
            throw new arithmeticexception(
                "not an element of the finite field this polynomial is defined over.");
        }
        int[] resultcoeff = multwithelement(coefficients, element);
        return new polynomialgf2msmallm(field, resultcoeff);
    }

    /**
     * multiply this polynomial with an element from gf(2^m).
     *
     * @param element an element of the finite field gf(2^m)
     * @throws arithmeticexception if <tt>element</tt> is not an element of the finite
     * field this polynomial is defined over.
     */
    public void multthiswithelement(int element)
    {
        if (!field.iselementofthisfield(element))
        {
            throw new arithmeticexception(
                "not an element of the finite field this polynomial is defined over.");
        }
        coefficients = multwithelement(coefficients, element);
        computedegree();
    }

    /**
     * compute the product of a polynomial a with an element from the finite
     * field <tt>gf(2^m)</tt>.
     *
     * @param a       the polynomial
     * @param element an element of the finite field gf(2^m)
     * @return <tt>a * element</tt>
     */
    private int[] multwithelement(int[] a, int element)
    {
        int degree = computedegree(a);
        if (degree == -1 || element == 0)
        {
            return new int[1];
        }

        if (element == 1)
        {
            return intutils.clone(a);
        }

        int[] result = new int[degree + 1];
        for (int i = degree; i >= 0; i--)
        {
            result[i] = field.mult(a[i], element);
        }

        return result;
    }

    /**
     * compute the product of this polynomial with a monomial x^k.
     *
     * @param k the degree of the monomial
     * @return <tt>this * x^k</tt>
     */
    public polynomialgf2msmallm multwithmonomial(int k)
    {
        int[] resultcoeff = multwithmonomial(coefficients, k);
        return new polynomialgf2msmallm(field, resultcoeff);
    }

    /**
     * compute the product of a polynomial with a monomial x^k.
     *
     * @param a the polynomial
     * @param k the degree of the monomial
     * @return <tt>a * x^k</tt>
     */
    private static int[] multwithmonomial(int[] a, int k)
    {
        int d = computedegree(a);
        if (d == -1)
        {
            return new int[1];
        }
        int[] result = new int[d + k + 1];
        system.arraycopy(a, 0, result, k, d + 1);
        return result;
    }

    /**
     * divide this polynomial by the given polynomial.
     *
     * @param f a polynomial
     * @return polynomial pair = {q,r} where this = q*f+r and deg(r) &lt;
     *         deg(f);
     */
    public polynomialgf2msmallm[] div(polynomialgf2msmallm f)
    {
        int[][] resultcoeffs = div(coefficients, f.coefficients);
        return new polynomialgf2msmallm[]{
            new polynomialgf2msmallm(field, resultcoeffs[0]),
            new polynomialgf2msmallm(field, resultcoeffs[1])};
    }

    /**
     * compute the result of the division of two polynomials over the field
     * <tt>gf(2^m)</tt>.
     *
     * @param a the first polynomial
     * @param f the second polynomial
     * @return int[][] {q,r}, where a = q*f+r and deg(r) &lt; deg(f);
     */
    private int[][] div(int[] a, int[] f)
    {
        int df = computedegree(f);
        int da = computedegree(a) + 1;
        if (df == -1)
        {
            throw new arithmeticexception("division by zero.");
        }
        int[][] result = new int[2][];
        result[0] = new int[1];
        result[1] = new int[da];
        int hc = headcoefficient(f);
        hc = field.inverse(hc);
        result[0][0] = 0;
        system.arraycopy(a, 0, result[1], 0, result[1].length);
        while (df <= computedegree(result[1]))
        {
            int[] q;
            int[] coeff = new int[1];
            coeff[0] = field.mult(headcoefficient(result[1]), hc);
            q = multwithelement(f, coeff[0]);
            int n = computedegree(result[1]) - df;
            q = multwithmonomial(q, n);
            coeff = multwithmonomial(coeff, n);
            result[0] = add(coeff, result[0]);
            result[1] = add(q, result[1]);
        }
        return result;
    }

    /**
     * return the greatest common divisor of this and a polynomial <i>f</i>
     *
     * @param f polynomial
     * @return gcd(this, f)
     */
    public polynomialgf2msmallm gcd(polynomialgf2msmallm f)
    {
        int[] resultcoeff = gcd(coefficients, f.coefficients);
        return new polynomialgf2msmallm(field, resultcoeff);
    }

    /**
     * return the greatest common divisor of two polynomials over the field
     * <tt>gf(2^m)</tt>.
     *
     * @param f the first polynomial
     * @param g the second polynomial
     * @return <tt>gcd(f, g)</tt>
     */
    private int[] gcd(int[] f, int[] g)
    {
        int[] a = f;
        int[] b = g;
        if (computedegree(a) == -1)
        {
            return b;
        }
        while (computedegree(b) != -1)
        {
            int[] c = mod(a, b);
            a = new int[b.length];
            system.arraycopy(b, 0, a, 0, a.length);
            b = new int[c.length];
            system.arraycopy(c, 0, b, 0, b.length);
        }
        int coeff = field.inverse(headcoefficient(a));
        return multwithelement(a, coeff);
    }

    /**
     * compute the product of this polynomial and the given factor using a
     * karatzuba like scheme.
     *
     * @param factor the polynomial
     * @return <tt>this * factor</tt>
     */
    public polynomialgf2msmallm multiply(polynomialgf2msmallm factor)
    {
        int[] resultcoeff = multiply(coefficients, factor.coefficients);
        return new polynomialgf2msmallm(field, resultcoeff);
    }

    /**
     * compute the product of two polynomials over the field <tt>gf(2^m)</tt>
     * using a karatzuba like multiplication.
     *
     * @param a the first polynomial
     * @param b the second polynomial
     * @return a * b
     */
    private int[] multiply(int[] a, int[] b)
    {
        int[] mult1, mult2;
        if (computedegree(a) < computedegree(b))
        {
            mult1 = b;
            mult2 = a;
        }
        else
        {
            mult1 = a;
            mult2 = b;
        }

        mult1 = normalform(mult1);
        mult2 = normalform(mult2);

        if (mult2.length == 1)
        {
            return multwithelement(mult1, mult2[0]);
        }

        int d1 = mult1.length;
        int d2 = mult2.length;
        int[] result = new int[d1 + d2 - 1];

        if (d2 != d1)
        {
            int[] res1 = new int[d2];
            int[] res2 = new int[d1 - d2];
            system.arraycopy(mult1, 0, res1, 0, res1.length);
            system.arraycopy(mult1, d2, res2, 0, res2.length);
            res1 = multiply(res1, mult2);
            res2 = multiply(res2, mult2);
            res2 = multwithmonomial(res2, d2);
            result = add(res1, res2);
        }
        else
        {
            d2 = (d1 + 1) >>> 1;
            int d = d1 - d2;
            int[] firstpartmult1 = new int[d2];
            int[] firstpartmult2 = new int[d2];
            int[] secondpartmult1 = new int[d];
            int[] secondpartmult2 = new int[d];
            system
                .arraycopy(mult1, 0, firstpartmult1, 0,
                    firstpartmult1.length);
            system.arraycopy(mult1, d2, secondpartmult1, 0,
                secondpartmult1.length);
            system
                .arraycopy(mult2, 0, firstpartmult2, 0,
                    firstpartmult2.length);
            system.arraycopy(mult2, d2, secondpartmult2, 0,
                secondpartmult2.length);
            int[] helppoly1 = add(firstpartmult1, secondpartmult1);
            int[] helppoly2 = add(firstpartmult2, secondpartmult2);
            int[] res1 = multiply(firstpartmult1, firstpartmult2);
            int[] res2 = multiply(helppoly1, helppoly2);
            int[] res3 = multiply(secondpartmult1, secondpartmult2);
            res2 = add(res2, res1);
            res2 = add(res2, res3);
            res3 = multwithmonomial(res3, d2);
            result = add(res2, res3);
            result = multwithmonomial(result, d2);
            result = add(result, res1);
        }

        return result;
    }

    /*
      * ---------------- part ii ----------------
      *
      */

    /**
     * check a polynomial for irreducibility over the field <tt>gf(2^m)</tt>.
     *
     * @param a the polynomial to check
     * @return true if a is irreducible, false otherwise
     */
    private boolean isirreducible(int[] a)
    {
        if (a[0] == 0)
        {
            return false;
        }
        int d = computedegree(a) >> 1;
        int[] u = {0, 1};
        final int[] y = {0, 1};
        int fielddegree = field.getdegree();
        for (int i = 0; i < d; i++)
        {
            for (int j = fielddegree - 1; j >= 0; j--)
            {
                u = modmultiply(u, u, a);
            }
            u = normalform(u);
            int[] g = gcd(add(u, y), a);
            if (computedegree(g) != 0)
            {
                return false;
            }
        }
        return true;
    }

    /**
     * reduce this polynomial modulo another polynomial.
     *
     * @param f the reduction polynomial
     * @return <tt>this mod f</tt>
     */
    public polynomialgf2msmallm mod(polynomialgf2msmallm f)
    {
        int[] resultcoeff = mod(coefficients, f.coefficients);
        return new polynomialgf2msmallm(field, resultcoeff);
    }

    /**
     * reduce a polynomial modulo another polynomial.
     *
     * @param a the polynomial
     * @param f the reduction polynomial
     * @return <tt>a mod f</tt>
     */
    private int[] mod(int[] a, int[] f)
    {
        int df = computedegree(f);
        if (df == -1)
        {
            throw new arithmeticexception("division by zero");
        }
        int[] result = new int[a.length];
        int hc = headcoefficient(f);
        hc = field.inverse(hc);
        system.arraycopy(a, 0, result, 0, result.length);
        while (df <= computedegree(result))
        {
            int[] q;
            int coeff = field.mult(headcoefficient(result), hc);
            q = multwithmonomial(f, computedegree(result) - df);
            q = multwithelement(q, coeff);
            result = add(q, result);
        }
        return result;
    }

    /**
     * compute the product of this polynomial and another polynomial modulo a
     * third polynomial.
     *
     * @param a another polynomial
     * @param b the reduction polynomial
     * @return <tt>this * a mod b</tt>
     */
    public polynomialgf2msmallm modmultiply(polynomialgf2msmallm a,
                                            polynomialgf2msmallm b)
    {
        int[] resultcoeff = modmultiply(coefficients, a.coefficients,
            b.coefficients);
        return new polynomialgf2msmallm(field, resultcoeff);
    }

    /**
     * square this polynomial using a squaring matrix.
     *
     * @param matrix the squaring matrix
     * @return <tt>this^2</tt> modulo the reduction polynomial implicitly
     *         given via the squaring matrix
     */
    public polynomialgf2msmallm modsquarematrix(polynomialgf2msmallm[] matrix)
    {

        int length = matrix.length;

        int[] resultcoeff = new int[length];
        int[] thissquare = new int[length];

        // square each entry of this polynomial
        for (int i = 0; i < coefficients.length; i++)
        {
            thissquare[i] = field.mult(coefficients[i], coefficients[i]);
        }

        // do matrix-vector multiplication
        for (int i = 0; i < length; i++)
        {
            // compute scalar product of i-th row and coefficient vector
            for (int j = 0; j < length; j++)
            {
                if (i >= matrix[j].coefficients.length)
                {
                    continue;
                }
                int scalarterm = field.mult(matrix[j].coefficients[i],
                    thissquare[j]);
                resultcoeff[i] = field.add(resultcoeff[i], scalarterm);
            }
        }

        return new polynomialgf2msmallm(field, resultcoeff);
    }

    /**
     * compute the product of two polynomials modulo a third polynomial over the
     * finite field <tt>gf(2^m)</tt>.
     *
     * @param a the first polynomial
     * @param b the second polynomial
     * @param g the reduction polynomial
     * @return <tt>a * b mod g</tt>
     */
    private int[] modmultiply(int[] a, int[] b, int[] g)
    {
        return mod(multiply(a, b), g);
    }

    /**
     * compute the square root of this polynomial modulo the given polynomial.
     *
     * @param a the reduction polynomial
     * @return <tt>this^(1/2) mod a</tt>
     */
    public polynomialgf2msmallm modsquareroot(polynomialgf2msmallm a)
    {
        int[] resultcoeff = intutils.clone(coefficients);
        int[] help = modmultiply(resultcoeff, resultcoeff, a.coefficients);
        while (!isequal(help, coefficients))
        {
            resultcoeff = normalform(help);
            help = modmultiply(resultcoeff, resultcoeff, a.coefficients);
        }

        return new polynomialgf2msmallm(field, resultcoeff);
    }

    /**
     * compute the square root of this polynomial using a square root matrix.
     *
     * @param matrix the matrix for computing square roots in
     *               <tt>(gf(2^m))^t</tt> the polynomial ring defining the
     *               square root matrix
     * @return <tt>this^(1/2)</tt> modulo the reduction polynomial implicitly
     *         given via the square root matrix
     */
    public polynomialgf2msmallm modsquarerootmatrix(
        polynomialgf2msmallm[] matrix)
    {

        int length = matrix.length;

        int[] resultcoeff = new int[length];

        // do matrix multiplication
        for (int i = 0; i < length; i++)
        {
            // compute scalar product of i-th row and j-th column
            for (int j = 0; j < length; j++)
            {
                if (i >= matrix[j].coefficients.length)
                {
                    continue;
                }
                if (j < coefficients.length)
                {
                    int scalarterm = field.mult(matrix[j].coefficients[i],
                        coefficients[j]);
                    resultcoeff[i] = field.add(resultcoeff[i], scalarterm);
                }
            }
        }

        // compute the square root of each entry of the result coefficients
        for (int i = 0; i < length; i++)
        {
            resultcoeff[i] = field.sqroot(resultcoeff[i]);
        }

        return new polynomialgf2msmallm(field, resultcoeff);
    }

    /**
     * compute the result of the division of this polynomial by another
     * polynomial modulo a third polynomial.
     *
     * @param divisor the divisor
     * @param modulus the reduction polynomial
     * @return <tt>this * divisor^(-1) mod modulus</tt>
     */
    public polynomialgf2msmallm moddiv(polynomialgf2msmallm divisor,
                                       polynomialgf2msmallm modulus)
    {
        int[] resultcoeff = moddiv(coefficients, divisor.coefficients,
            modulus.coefficients);
        return new polynomialgf2msmallm(field, resultcoeff);
    }

    /**
     * compute the result of the division of two polynomials modulo a third
     * polynomial over the field <tt>gf(2^m)</tt>.
     *
     * @param a the first polynomial
     * @param b the second polynomial
     * @param g the reduction polynomial
     * @return <tt>a * b^(-1) mod g</tt>
     */
    private int[] moddiv(int[] a, int[] b, int[] g)
    {
        int[] r0 = normalform(g);
        int[] r1 = mod(b, g);
        int[] s0 = {0};
        int[] s1 = mod(a, g);
        int[] s2;
        int[][] q;
        while (computedegree(r1) != -1)
        {
            q = div(r0, r1);
            r0 = normalform(r1);
            r1 = normalform(q[1]);
            s2 = add(s0, modmultiply(q[0], s1, g));
            s0 = normalform(s1);
            s1 = normalform(s2);

        }
        int hc = headcoefficient(r0);
        s0 = multwithelement(s0, field.inverse(hc));
        return s0;
    }

    /**
     * compute the inverse of this polynomial modulo the given polynomial.
     *
     * @param a the reduction polynomial
     * @return <tt>this^(-1) mod a</tt>
     */
    public polynomialgf2msmallm modinverse(polynomialgf2msmallm a)
    {
        int[] unit = {1};
        int[] resultcoeff = moddiv(unit, coefficients, a.coefficients);
        return new polynomialgf2msmallm(field, resultcoeff);
    }

    /**
     * compute a polynomial pair (a,b) from this polynomial and the given
     * polynomial g with the property b*this = a mod g and deg(a)<=deg(g)/2.
     *
     * @param g the reduction polynomial
     * @return polynomialgf2msmallm[] {a,b} with b*this = a mod g and deg(a)<=
     *         deg(g)/2
     */
    public polynomialgf2msmallm[] modpolynomialtofracton(polynomialgf2msmallm g)
    {
        int dg = g.degree >> 1;
        int[] a0 = normalform(g.coefficients);
        int[] a1 = mod(coefficients, g.coefficients);
        int[] b0 = {0};
        int[] b1 = {1};
        while (computedegree(a1) > dg)
        {
            int[][] q = div(a0, a1);
            a0 = a1;
            a1 = q[1];
            int[] b2 = add(b0, modmultiply(q[0], b1, g.coefficients));
            b0 = b1;
            b1 = b2;
        }

        return new polynomialgf2msmallm[]{
            new polynomialgf2msmallm(field, a1),
            new polynomialgf2msmallm(field, b1)};
    }

    /**
     * checks if given object is equal to this polynomial.
     * <p/>
     * the method returns false whenever the given object is not polynomial over
     * gf(2^m).
     *
     * @param other object
     * @return true or false
     */
    public boolean equals(object other)
    {

        if (other == null || !(other instanceof polynomialgf2msmallm))
        {
            return false;
        }

        polynomialgf2msmallm p = (polynomialgf2msmallm)other;

        if ((field.equals(p.field)) && (degree == p.degree)
            && (isequal(coefficients, p.coefficients)))
        {
            return true;
        }

        return false;
    }

    /**
     * compare two polynomials given as int arrays.
     *
     * @param a the first polynomial
     * @param b the second polynomial
     * @return <tt>true</tt> if <tt>a</tt> and <tt>b</tt> represent the
     *         same polynomials, <tt>false</tt> otherwise
     */
    private static boolean isequal(int[] a, int[] b)
    {
        int da = computedegree(a);
        int db = computedegree(b);
        if (da != db)
        {
            return false;
        }
        for (int i = 0; i <= da; i++)
        {
            if (a[i] != b[i])
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
        int hash = field.hashcode();
        for (int j = 0; j < coefficients.length; j++)
        {
            hash = hash * 31 + coefficients[j];
        }
        return hash;
    }

    /**
     * returns a human readable form of the polynomial.
     * <p/>
     *
     * @return a human readable form of the polynomial.
     */
    public string tostring()
    {
        string str = " polynomial over " + field.tostring() + ": \n";

        for (int i = 0; i < coefficients.length; i++)
        {
            str = str + field.elementtostr(coefficients[i]) + "y^" + i + "+";
        }
        str = str + ";";

        return str;
    }

    /**
     * compute the degree of this polynomial. if this is the zero polynomial,
     * the degree is -1.
     */
    private void computedegree()
    {
        for (degree = coefficients.length - 1; degree >= 0
            && coefficients[degree] == 0; degree--)
        {
            ;
        }
    }

    /**
     * compute the degree of a polynomial.
     *
     * @param a the polynomial
     * @return the degree of the polynomial <tt>a</tt>. if <tt>a</tt> is
     *         the zero polynomial, return -1.
     */
    private static int computedegree(int[] a)
    {
        int degree;
        for (degree = a.length - 1; degree >= 0 && a[degree] == 0; degree--)
        {
            ;
        }
        return degree;
    }

    /**
     * strip leading zero coefficients from the given polynomial.
     *
     * @param a the polynomial
     * @return the reduced polynomial
     */
    private static int[] normalform(int[] a)
    {
        int d = computedegree(a);

        // if a is the zero polynomial
        if (d == -1)
        {
            // return new zero polynomial
            return new int[1];
        }

        // if a already is in normal form
        if (a.length == d + 1)
        {
            // return a clone of a
            return intutils.clone(a);
        }

        // else, reduce a
        int[] result = new int[d + 1];
        system.arraycopy(a, 0, result, 0, d + 1);
        return result;
    }

}
