package org.ripple.bouncycastle.pqc.crypto.ntru;

import java.io.ioexception;
import java.io.inputstream;
import java.io.outputstream;

import org.ripple.bouncycastle.crypto.params.asymmetrickeyparameter;
import org.ripple.bouncycastle.pqc.math.ntru.polynomial.integerpolynomial;

/**
 * a ntrusign public key is essentially a polynomial named <code>h</code>.
 */
public class ntrusigningpublickeyparameters
    extends asymmetrickeyparameter
{
    private ntrusigningparameters params;
    public integerpolynomial h;

    /**
     * constructs a new public key from a polynomial
     *
     * @param h      the polynomial <code>h</code> which determines the key
     * @param params the ntrusign parameters to use
     */
    public ntrusigningpublickeyparameters(integerpolynomial h, ntrusigningparameters params)
    {
        super(false);
        this.h = h;
        this.params = params;
    }

    /**
     * converts a byte array to a polynomial <code>h</code> and constructs a new public key
     *
     * @param b      an encoded polynomial
     * @param params the ntrusign parameters to use
     */
    public ntrusigningpublickeyparameters(byte[] b, ntrusigningparameters params)
    {
        super(false);
        h = integerpolynomial.frombinary(b, params.n, params.q);
        this.params = params;
    }

    /**
     * reads a polynomial <code>h</code> from an input stream and constructs a new public key
     *
     * @param is     an input stream
     * @param params the ntrusign parameters to use
     */
    public ntrusigningpublickeyparameters(inputstream is, ntrusigningparameters params)
        throws ioexception
    {
        super(false);
        h = integerpolynomial.frombinary(is, params.n, params.q);
        this.params = params;
    }


    /**
     * converts the key to a byte array
     *
     * @return the encoded key
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
     */
    public void writeto(outputstream os)
        throws ioexception
    {
        os.write(getencoded());
    }

    @override
    public int hashcode()
    {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((h == null) ? 0 : h.hashcode());
        result = prime * result + ((params == null) ? 0 : params.hashcode());
        return result;
    }

    @override
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
        ntrusigningpublickeyparameters other = (ntrusigningpublickeyparameters)obj;
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