package org.ripple.bouncycastle.pqc.math.ntru.polynomial;

import java.io.bytearrayinputstream;
import java.io.ioexception;
import java.io.inputstream;
import java.security.securerandom;

import org.ripple.bouncycastle.util.arrays;

/**
 * a polynomial of the form <code>f1*f2+f3</code>, where
 * <code>f1,f2,f3</code> are very sparsely populated ternary polynomials.
 */
public class productformpolynomial
    implements polynomial
{
    private sparseternarypolynomial f1, f2, f3;

    public productformpolynomial(sparseternarypolynomial f1, sparseternarypolynomial f2, sparseternarypolynomial f3)
    {
        this.f1 = f1;
        this.f2 = f2;
        this.f3 = f3;
    }

    public static productformpolynomial generaterandom(int n, int df1, int df2, int df3ones, int df3negones, securerandom random)
    {
        sparseternarypolynomial f1 = sparseternarypolynomial.generaterandom(n, df1, df1, random);
        sparseternarypolynomial f2 = sparseternarypolynomial.generaterandom(n, df2, df2, random);
        sparseternarypolynomial f3 = sparseternarypolynomial.generaterandom(n, df3ones, df3negones, random);
        return new productformpolynomial(f1, f2, f3);
    }

    public static productformpolynomial frombinary(byte[] data, int n, int df1, int df2, int df3ones, int df3negones)
        throws ioexception
    {
        return frombinary(new bytearrayinputstream(data), n, df1, df2, df3ones, df3negones);
    }

    public static productformpolynomial frombinary(inputstream is, int n, int df1, int df2, int df3ones, int df3negones)
        throws ioexception
    {
        sparseternarypolynomial f1;

        f1 = sparseternarypolynomial.frombinary(is, n, df1, df1);
        sparseternarypolynomial f2 = sparseternarypolynomial.frombinary(is, n, df2, df2);
        sparseternarypolynomial f3 = sparseternarypolynomial.frombinary(is, n, df3ones, df3negones);
        return new productformpolynomial(f1, f2, f3);
    }

    public byte[] tobinary()
    {
        byte[] f1bin = f1.tobinary();
        byte[] f2bin = f2.tobinary();
        byte[] f3bin = f3.tobinary();

        byte[] all = arrays.copyof(f1bin, f1bin.length + f2bin.length + f3bin.length);
        system.arraycopy(f2bin, 0, all, f1bin.length, f2bin.length);
        system.arraycopy(f3bin, 0, all, f1bin.length + f2bin.length, f3bin.length);
        return all;
    }

    public integerpolynomial mult(integerpolynomial b)
    {
        integerpolynomial c = f1.mult(b);
        c = f2.mult(c);
        c.add(f3.mult(b));
        return c;
    }

    public bigintpolynomial mult(bigintpolynomial b)
    {
        bigintpolynomial c = f1.mult(b);
        c = f2.mult(c);
        c.add(f3.mult(b));
        return c;
    }

    public integerpolynomial tointegerpolynomial()
    {
        integerpolynomial i = f1.mult(f2.tointegerpolynomial());
        i.add(f3.tointegerpolynomial());
        return i;
    }

    public integerpolynomial mult(integerpolynomial poly2, int modulus)
    {
        integerpolynomial c = mult(poly2);
        c.mod(modulus);
        return c;
    }

    public int hashcode()
    {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((f1 == null) ? 0 : f1.hashcode());
        result = prime * result + ((f2 == null) ? 0 : f2.hashcode());
        result = prime * result + ((f3 == null) ? 0 : f3.hashcode());
        return result;
    }

    public boolean equals(object obj)
    {
        if (this == obj)
        {
            return true;
        }
        if (obj == null)
        {
            return false;
        }
        if (getclass() != obj.getclass())
        {
            return false;
        }
        productformpolynomial other = (productformpolynomial)obj;
        if (f1 == null)
        {
            if (other.f1 != null)
            {
                return false;
            }
        }
        else if (!f1.equals(other.f1))
        {
            return false;
        }
        if (f2 == null)
        {
            if (other.f2 != null)
            {
                return false;
            }
        }
        else if (!f2.equals(other.f2))
        {
            return false;
        }
        if (f3 == null)
        {
            if (other.f3 != null)
            {
                return false;
            }
        }
        else if (!f3.equals(other.f3))
        {
            return false;
        }
        return true;
    }
}
