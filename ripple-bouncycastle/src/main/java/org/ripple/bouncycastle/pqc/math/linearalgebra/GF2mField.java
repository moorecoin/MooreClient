package org.ripple.bouncycastle.pqc.math.linearalgebra;

import java.security.securerandom;

/**
 * this class describes operations with elements from the finite field f =
 * gf(2^m). ( gf(2^m)= gf(2)[a] where a is a root of irreducible polynomial with
 * degree m, each field element b has a polynomial basis representation, i.e. it
 * is represented by a different binary polynomial of degree less than m, b =
 * poly(a) ) all operations are defined only for field with 1< m <32. for the
 * representation of field elements the map f: f->z, poly(a)->poly(2) is used,
 * where integers have the binary representation. for example: a^7+a^3+a+1 ->
 * (00...0010001011)=139 also for elements type integer is used.
 *
 * @see polynomialringgf2
 */
public class gf2mfield
{

    /*
      * degree - degree of the field polynomial - the field polynomial ring -
      * polynomial ring over the finite field gf(2)
      */

    private int degree = 0;

    private int polynomial;

    /**
     * create a finite field gf(2^m)
     *
     * @param degree the degree of the field
     */
    public gf2mfield(int degree)
    {
        if (degree >= 32)
        {
            throw new illegalargumentexception(
                " error: the degree of field is too large ");
        }
        if (degree < 1)
        {
            throw new illegalargumentexception(
                " error: the degree of field is non-positive ");
        }
        this.degree = degree;
        polynomial = polynomialringgf2.getirreduciblepolynomial(degree);
    }

    /**
     * create a finite field gf(2^m) with the fixed field polynomial
     *
     * @param degree the degree of the field
     * @param poly   the field polynomial
     */
    public gf2mfield(int degree, int poly)
    {
        if (degree != polynomialringgf2.degree(poly))
        {
            throw new illegalargumentexception(
                " error: the degree is not correct");
        }
        if (!polynomialringgf2.isirreducible(poly))
        {
            throw new illegalargumentexception(
                " error: given polynomial is reducible");
        }
        this.degree = degree;
        polynomial = poly;

    }

    public gf2mfield(byte[] enc)
    {
        if (enc.length != 4)
        {
            throw new illegalargumentexception(
                "byte array is not an encoded finite field");
        }
        polynomial = littleendianconversions.os2ip(enc);
        if (!polynomialringgf2.isirreducible(polynomial))
        {
            throw new illegalargumentexception(
                "byte array is not an encoded finite field");
        }

        degree = polynomialringgf2.degree(polynomial);
    }

    public gf2mfield(gf2mfield field)
    {
        degree = field.degree;
        polynomial = field.polynomial;
    }

    /**
     * return degree of the field
     *
     * @return degree of the field
     */
    public int getdegree()
    {
        return degree;
    }

    /**
     * return the field polynomial
     *
     * @return the field polynomial
     */
    public int getpolynomial()
    {
        return polynomial;
    }

    /**
     * return the encoded form of this field
     *
     * @return the field in byte array form
     */
    public byte[] getencoded()
    {
        return littleendianconversions.i2osp(polynomial);
    }

    /**
     * return sum of two elements
     *
     * @param a
     * @param b
     * @return a+b
     */
    public int add(int a, int b)
    {
        return a ^ b;
    }

    /**
     * return product of two elements
     *
     * @param a
     * @param b
     * @return a*b
     */
    public int mult(int a, int b)
    {
        return polynomialringgf2.modmultiply(a, b, polynomial);
    }

    /**
     * compute exponentiation a^k
     *
     * @param a a field element a
     * @param k k degree
     * @return a^k
     */
    public int exp(int a, int k)
    {
        if (a == 0)
        {
            return 0;
        }
        if (a == 1)
        {
            return 1;
        }
        int result = 1;
        if (k < 0)
        {
            a = inverse(a);
            k = -k;
        }
        while (k != 0)
        {
            if ((k & 1) == 1)
            {
                result = mult(result, a);
            }
            a = mult(a, a);
            k >>>= 1;
        }
        return result;
    }

    /**
     * compute the multiplicative inverse of a
     *
     * @param a a field element a
     * @return a<sup>-1</sup>
     */
    public int inverse(int a)
    {
        int d = (1 << degree) - 2;

        return exp(a, d);
    }

    /**
     * compute the square root of an integer
     *
     * @param a a field element a
     * @return a<sup>1/2</sup>
     */
    public int sqroot(int a)
    {
        for (int i = 1; i < degree; i++)
        {
            a = mult(a, a);
        }
        return a;
    }

    /**
     * create a random field element using prng sr
     *
     * @param sr securerandom
     * @return a random element
     */
    public int getrandomelement(securerandom sr)
    {
        int result = randutils.nextint(sr, 1 << degree);
        return result;
    }

    /**
     * create a random non-zero field element
     *
     * @return a random element
     */
    public int getrandomnonzeroelement()
    {
        return getrandomnonzeroelement(new securerandom());
    }

    /**
     * create a random non-zero field element using prng sr
     *
     * @param sr securerandom
     * @return a random non-zero element
     */
    public int getrandomnonzeroelement(securerandom sr)
    {
        int controltime = 1 << 20;
        int count = 0;
        int result = randutils.nextint(sr, 1 << degree);
        while ((result == 0) && (count < controltime))
        {
            result = randutils.nextint(sr, 1 << degree);
            count++;
        }
        if (count == controltime)
        {
            result = 1;
        }
        return result;
    }

    /**
     * @return true if e is encoded element of this field and false otherwise
     */
    public boolean iselementofthisfield(int e)
    {
        // e is encoded element of this field iff 0<= e < |2^m|
        if (degree == 31)
        {
            return e >= 0;
        }
        return e >= 0 && e < (1 << degree);
    }

    /*
      * help method for visual control
      */
    public string elementtostr(int a)
    {
        string s = "";
        for (int i = 0; i < degree; i++)
        {
            if (((byte)a & 0x01) == 0)
            {
                s = "0" + s;
            }
            else
            {
                s = "1" + s;
            }
            a >>>= 1;
        }
        return s;
    }

    /**
     * checks if given object is equal to this field.
     * <p/>
     * the method returns false whenever the given object is not gf2m.
     *
     * @param other object
     * @return true or false
     */
    public boolean equals(object other)
    {
        if ((other == null) || !(other instanceof gf2mfield))
        {
            return false;
        }

        gf2mfield otherfield = (gf2mfield)other;

        if ((degree == otherfield.degree)
            && (polynomial == otherfield.polynomial))
        {
            return true;
        }

        return false;
    }

    public int hashcode()
    {
        return polynomial;
    }

    /**
     * returns a human readable form of this field.
     * <p/>
     *
     * @return a human readable form of this field.
     */
    public string tostring()
    {
        string str = "finite field gf(2^" + degree + ") = " + "gf(2)[x]/<"
            + polytostring(polynomial) + "> ";
        return str;
    }

    private static string polytostring(int p)
    {
        string str = "";
        if (p == 0)
        {
            str = "0";
        }
        else
        {
            byte b = (byte)(p & 0x01);
            if (b == 1)
            {
                str = "1";
            }
            p >>>= 1;
            int i = 1;
            while (p != 0)
            {
                b = (byte)(p & 0x01);
                if (b == 1)
                {
                    str = str + "+x^" + i;
                }
                p >>>= 1;
                i++;
            }
        }
        return str;
    }

}
