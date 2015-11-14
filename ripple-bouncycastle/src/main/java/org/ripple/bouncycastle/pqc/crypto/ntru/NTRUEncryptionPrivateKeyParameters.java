package org.ripple.bouncycastle.pqc.crypto.ntru;

import java.io.bytearrayinputstream;
import java.io.ioexception;
import java.io.inputstream;
import java.io.outputstream;

import org.ripple.bouncycastle.pqc.math.ntru.polynomial.denseternarypolynomial;
import org.ripple.bouncycastle.pqc.math.ntru.polynomial.integerpolynomial;
import org.ripple.bouncycastle.pqc.math.ntru.polynomial.polynomial;
import org.ripple.bouncycastle.pqc.math.ntru.polynomial.productformpolynomial;
import org.ripple.bouncycastle.pqc.math.ntru.polynomial.sparseternarypolynomial;

/**
 * a ntruencrypt private key is essentially a polynomial named <code>f</code>
 * which takes different forms depending on whether product-form polynomials are used,
 * and on <code>fastp</code><br/>
 * the inverse of <code>f</code> modulo <code>p</code> is precomputed on initialization.
 */
public class ntruencryptionprivatekeyparameters
    extends ntruencryptionkeyparameters
{
    public polynomial t;
    public integerpolynomial fp;
    public integerpolynomial h;

    /**
     * constructs a new private key from a polynomial
     *
     * @param h the public polynomial for the key.
     * @param t      the polynomial which determines the key: if <code>fastfp=true</code>, <code>f=1+3t</code>; otherwise, <code>f=t</code>
     * @param fp     the inverse of <code>f</code>
     * @param params the ntruencrypt parameters to use
     */
    public ntruencryptionprivatekeyparameters(integerpolynomial h, polynomial t, integerpolynomial fp, ntruencryptionparameters params)
    {
        super(true, params);

        this.h = h;
        this.t = t;
        this.fp = fp;
    }

    /**
     * converts a byte array to a polynomial <code>f</code> and constructs a new private key
     *
     * @param b      an encoded polynomial
     * @param params the ntruencrypt parameters to use
     * @see #getencoded()
     */
    public ntruencryptionprivatekeyparameters(byte[] b, ntruencryptionparameters params)
        throws ioexception
    {
        this(new bytearrayinputstream(b), params);
    }

    /**
     * reads a polynomial <code>f</code> from an input stream and constructs a new private key
     *
     * @param is     an input stream
     * @param params the ntruencrypt parameters to use
     * @see #writeto(outputstream)
     */
    public ntruencryptionprivatekeyparameters(inputstream is, ntruencryptionparameters params)
        throws ioexception
    {
        super(true, params);

        if (params.polytype == ntruparameters.ternary_polynomial_type_product)
        {
            int n = params.n;
            int df1 = params.df1;
            int df2 = params.df2;
            int df3ones = params.df3;
            int df3negones = params.fastfp ? params.df3 : params.df3 - 1;
            h = integerpolynomial.frombinary(is, params.n, params.q);
            t = productformpolynomial.frombinary(is, n, df1, df2, df3ones, df3negones);
        }
        else
        {
            h = integerpolynomial.frombinary(is, params.n, params.q);
            integerpolynomial fint = integerpolynomial.frombinary3tight(is, params.n);
            t = params.sparse ? new sparseternarypolynomial(fint) : new denseternarypolynomial(fint);
        }

        init();
    }

    /**
     * initializes <code>fp</code> from t.
     */
    private void init()
    {
        if (params.fastfp)
        {
            fp = new integerpolynomial(params.n);
            fp.coeffs[0] = 1;
        }
        else
        {
            fp = t.tointegerpolynomial().invertf3();
        }
    }

    /**
     * converts the key to a byte array
     *
     * @return the encoded key
     * @see #ntruencryptionprivatekeyparameters(byte[], ntruencryptionparameters)
     */
    public byte[] getencoded()
    {
        byte[] hbytes = h.tobinary(params.q);
        byte[] tbytes;

        if (t instanceof productformpolynomial)
        {
            tbytes = ((productformpolynomial)t).tobinary();
        }
        else
        {
            tbytes = t.tointegerpolynomial().tobinary3tight();
        }

        byte[] res = new byte[hbytes.length + tbytes.length];

        system.arraycopy(hbytes, 0, res, 0, hbytes.length);
        system.arraycopy(tbytes, 0, res, hbytes.length, tbytes.length);

        return res;
    }

    /**
     * writes the key to an output stream
     *
     * @param os an output stream
     * @throws ioexception
     * @see #ntruencryptionprivatekeyparameters(inputstream, ntruencryptionparameters)
     */
    public void writeto(outputstream os)
        throws ioexception
    {
        os.write(getencoded());
    }

    public int hashcode()
    {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((params == null) ? 0 : params.hashcode());
        result = prime * result + ((t == null) ? 0 : t.hashcode());
        result = prime * result + ((h == null) ? 0 : h.hashcode());
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
        if (!(obj instanceof ntruencryptionprivatekeyparameters))
        {
            return false;
        }
        ntruencryptionprivatekeyparameters other = (ntruencryptionprivatekeyparameters)obj;
        if (params == null)
        {
            if (other.params != null)
            {
                return false;
            }
        }
        else if (!params.equals(other.params))
        {
            return false;
        }
        if (t == null)
        {
            if (other.t != null)
            {
                return false;
            }
        }
        else if (!t.equals(other.t))
        {
            return false;
        }
        if (!h.equals(other.h))
        {
            return false;
        }
        return true;
    }
}