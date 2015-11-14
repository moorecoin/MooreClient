package org.ripple.bouncycastle.pqc.crypto.mceliece;

import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.pqc.math.linearalgebra.polynomialringgf2;

public class mcelieceparameters
    implements cipherparameters
{

    /**
     * the default extension degree
     */
    public static final int default_m = 11;

    /**
     * the default error correcting capability.
     */
    public static final int default_t = 50;

    /**
     * extension degree of the finite field gf(2^m)
     */
    private int m;

    /**
     * error correction capability of the code
     */
    private int t;

    /**
     * length of the code
     */
    private int n;

    /**
     * the field polynomial
     */
    private int fieldpoly;

    /**
     * constructor. set the default parameters: extension degree.
     */
    public mcelieceparameters()
    {
        this(default_m, default_t);
    }

    /**
     * constructor.
     *
     * @param keysize the length of a goppa code
     * @throws illegalargumentexception if <tt>keysize &lt; 1</tt>.
     */
    public mcelieceparameters(int keysize)
        throws illegalargumentexception
    {
        if (keysize < 1)
        {
            throw new illegalargumentexception("key size must be positive");
        }
        m = 0;
        n = 1;
        while (n < keysize)
        {
            n <<= 1;
            m++;
        }
        t = n >>> 1;
        t /= m;
        fieldpoly = polynomialringgf2.getirreduciblepolynomial(m);
    }

    /**
     * constructor.
     *
     * @param m degree of the finite field gf(2^m)
     * @param t error correction capability of the code
     * @throws illegalargumentexception if <tt>m &lt; 1</tt> or <tt>m &gt; 32</tt> or
     * <tt>t &lt; 0</tt> or <tt>t &gt; n</tt>.
     */
    public mcelieceparameters(int m, int t)
        throws illegalargumentexception
    {
        if (m < 1)
        {
            throw new illegalargumentexception("m must be positive");
        }
        if (m > 32)
        {
            throw new illegalargumentexception("m is too large");
        }
        this.m = m;
        n = 1 << m;
        if (t < 0)
        {
            throw new illegalargumentexception("t must be positive");
        }
        if (t > n)
        {
            throw new illegalargumentexception("t must be less than n = 2^m");
        }
        this.t = t;
        fieldpoly = polynomialringgf2.getirreduciblepolynomial(m);
    }

    /**
     * constructor.
     *
     * @param m    degree of the finite field gf(2^m)
     * @param t    error correction capability of the code
     * @param poly the field polynomial
     * @throws illegalargumentexception if <tt>m &lt; 1</tt> or <tt>m &gt; 32</tt> or
     * <tt>t &lt; 0</tt> or <tt>t &gt; n</tt> or
     * <tt>poly</tt> is not an irreducible field polynomial.
     */
    public mcelieceparameters(int m, int t, int poly)
        throws illegalargumentexception
    {
        this.m = m;
        if (m < 1)
        {
            throw new illegalargumentexception("m must be positive");
        }
        if (m > 32)
        {
            throw new illegalargumentexception(" m is too large");
        }
        this.n = 1 << m;
        this.t = t;
        if (t < 0)
        {
            throw new illegalargumentexception("t must be positive");
        }
        if (t > n)
        {
            throw new illegalargumentexception("t must be less than n = 2^m");
        }
        if ((polynomialringgf2.degree(poly) == m)
            && (polynomialringgf2.isirreducible(poly)))
        {
            this.fieldpoly = poly;
        }
        else
        {
            throw new illegalargumentexception(
                "polynomial is not a field polynomial for gf(2^m)");
        }
    }

    /**
     * @return the extension degree of the finite field gf(2^m)
     */
    public int getm()
    {
        return m;
    }

    /**
     * @return the length of the code
     */
    public int getn()
    {
        return n;
    }

    /**
     * @return the error correction capability of the code
     */
    public int gett()
    {
        return t;
    }

    /**
     * @return the field polynomial
     */
    public int getfieldpoly()
    {
        return fieldpoly;
    }
}
