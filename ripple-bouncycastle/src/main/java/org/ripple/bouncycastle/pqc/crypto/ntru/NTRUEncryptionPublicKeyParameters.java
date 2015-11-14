package org.ripple.bouncycastle.pqc.crypto.ntru;

import java.io.ioexception;
import java.io.inputstream;
import java.io.outputstream;

import org.ripple.bouncycastle.pqc.math.ntru.polynomial.integerpolynomial;

/**
 * a ntruencrypt public key is essentially a polynomial named <code>h</code>.
 */
public class ntruencryptionpublickeyparameters
    extends ntruencryptionkeyparameters
{
    public integerpolynomial h;

    /**
     * constructs a new public key from a polynomial
     *
     * @param h      the polynomial <code>h</code> which determines the key
     * @param params the ntruencrypt parameters to use
     */
    public ntruencryptionpublickeyparameters(integerpolynomial h, ntruencryptionparameters params)
    {
        super(false, params);

        this.h = h;
    }

    /**
     * converts a byte array to a polynomial <code>h</code> and constructs a new public key
     *
     * @param b      an encoded polynomial
     * @param params the ntruencrypt parameters to use
     * @see #getencoded()
     */
    public ntruencryptionpublickeyparameters(byte[] b, ntruencryptionparameters params)
    {
        super(false, params);

        h = integerpolynomial.frombinary(b, params.n, params.q);
    }

    /**
     * reads a polynomial <code>h</code> from an input stream and constructs a new public key
     *
     * @param is     an input stream
     * @param params the ntruencrypt parameters to use
     * @see #writeto(outputstream)
     */
    public ntruencryptionpublickeyparameters(inputstream is, ntruencryptionparameters params)
        throws ioexception
    {
        super(false, params);

        h = integerpolynomial.frombinary(is, params.n, params.q);
    }

    /**
     * converts the key to a byte array
     *
     * @return the encoded key
     * @see #ntruencryptionpublickeyparameters(byte[], ntruencryptionparameters)
     */
    public byte[] getencoded()
    {
        return h.tobinary(params.q);
    }

    /**
     * writes the key to an output stream
     *
     * @param os an output stream
     * @throws ioexception
     * @see #ntruencryptionpublickeyparameters(inputstream, ntruencryptionparameters)
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
        result = prime * result + ((h == null) ? 0 : h.hashcode());
        result = prime * result + ((params == null) ? 0 : params.hashcode());
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
        if (!(obj instanceof ntruencryptionpublickeyparameters))
        {
            return false;
        }
        ntruencryptionpublickeyparameters other = (ntruencryptionpublickeyparameters)obj;
        if (h == null)
        {
            if (other.h != null)
            {
                return false;
            }
        }
        else if (!h.equals(other.h))
        {
            return false;
        }
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
        return true;
    }
}