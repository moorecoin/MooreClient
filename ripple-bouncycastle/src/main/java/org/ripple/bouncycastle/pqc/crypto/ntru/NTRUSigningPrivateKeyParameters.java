package org.ripple.bouncycastle.pqc.crypto.ntru;

import java.io.bytearrayinputstream;
import java.io.bytearrayoutputstream;
import java.io.ioexception;
import java.io.inputstream;
import java.io.outputstream;
import java.util.arraylist;
import java.util.list;

import org.ripple.bouncycastle.crypto.params.asymmetrickeyparameter;
import org.ripple.bouncycastle.pqc.math.ntru.polynomial.denseternarypolynomial;
import org.ripple.bouncycastle.pqc.math.ntru.polynomial.integerpolynomial;
import org.ripple.bouncycastle.pqc.math.ntru.polynomial.polynomial;
import org.ripple.bouncycastle.pqc.math.ntru.polynomial.productformpolynomial;
import org.ripple.bouncycastle.pqc.math.ntru.polynomial.sparseternarypolynomial;

/**
 * a ntrusign private key comprises one or more {@link ntrusigningprivatekeyparameters.basis} of three polynomials each,
 * except the zeroth basis for which <code>h</code> is undefined.
 */
public class ntrusigningprivatekeyparameters
    extends asymmetrickeyparameter
{
    private list<basis> bases;
    private ntrusigningpublickeyparameters publickey;

    /**
     * constructs a new private key from a byte array
     *
     * @param b      an encoded private key
     * @param params the ntrusign parameters to use
     */
    public ntrusigningprivatekeyparameters(byte[] b, ntrusigningkeygenerationparameters params)
        throws ioexception
    {
        this(new bytearrayinputstream(b), params);
    }

    /**
     * constructs a new private key from an input stream
     *
     * @param is     an input stream
     * @param params the ntrusign parameters to use
     */
    public ntrusigningprivatekeyparameters(inputstream is, ntrusigningkeygenerationparameters params)
        throws ioexception
    {
        super(true);
        bases = new arraylist<basis>();
        for (int i = 0; i <= params.b; i++)
        // include a public key h[i] in all bases except for the first one
        {
            add(new basis(is, params, i != 0));
        }
        publickey = new ntrusigningpublickeyparameters(is, params.getsigningparameters());
    }

    public ntrusigningprivatekeyparameters(list<basis> bases, ntrusigningpublickeyparameters publickey)
    {
        super(true);
        this.bases = new arraylist<basis>(bases);
        this.publickey = publickey;
    }

    /**
     * adds a basis to the key.
     *
     * @param b a ntrusign basis
     */
    private void add(basis b)
    {
        bases.add(b);
    }

    /**
     * returns the <code>i</code>-th basis
     *
     * @param i the index
     * @return the basis at index <code>i</code>
     */
    public basis getbasis(int i)
    {
        return bases.get(i);
    }

    public ntrusigningpublickeyparameters getpublickey()
    {
        return publickey;
    }

    /**
     * converts the key to a byte array
     *
     * @return the encoded key
     */
    public byte[] getencoded()
        throws ioexception
    {
        bytearrayoutputstream os = new bytearrayoutputstream();
        for (int i = 0; i < bases.size(); i++)
        {
            // all bases except for the first one contain a public key
            bases.get(i).encode(os, i != 0);
        }

        os.write(publickey.getencoded());

        return os.tobytearray();
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
        result = prime * result + ((bases == null) ? 0 : bases.hashcode());
        for (basis basis : bases)
        {
            result += basis.hashcode();
        }
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
        ntrusigningprivatekeyparameters other = (ntrusigningprivatekeyparameters)obj;
        if (bases == null)
        {
            if (other.bases != null)
            {
                return false;
            }
        }
        if (bases.size() != other.bases.size())
        {
            return false;
        }
        for (int i = 0; i < bases.size(); i++)
        {
            basis basis1 = bases.get(i);
            basis basis2 = other.bases.get(i);
            if (!basis1.f.equals(basis2.f))
            {
                return false;
            }
            if (!basis1.fprime.equals(basis2.fprime))
            {
                return false;
            }
            if (i != 0 && !basis1.h.equals(basis2.h))   // don't compare h for the 0th basis
            {
                return false;
            }
            if (!basis1.params.equals(basis2.params))
            {
                return false;
            }
        }
        return true;
    }

    /**
     * a ntrusign basis. contains three polynomials <code>f, f', h</code>.
     */
    public static class basis
    {
        public polynomial f;
        public polynomial fprime;
        public integerpolynomial h;
        ntrusigningkeygenerationparameters params;

        /**
         * constructs a new basis from polynomials <code>f, f', h</code>.
         *
         * @param f
         * @param fprime
         * @param h
         * @param params ntrusign parameters
         */
        protected basis(polynomial f, polynomial fprime, integerpolynomial h, ntrusigningkeygenerationparameters params)
        {
            this.f = f;
            this.fprime = fprime;
            this.h = h;
            this.params = params;
        }

        /**
         * reads a basis from an input stream and constructs a new basis.
         *
         * @param is        an input stream
         * @param params    ntrusign parameters
         * @param include_h whether to read the polynomial <code>h</code> (<code>true</code>) or only <code>f</code> and <code>f'</code> (<code>false</code>)
         */
        basis(inputstream is, ntrusigningkeygenerationparameters params, boolean include_h)
            throws ioexception
        {
            int n = params.n;
            int q = params.q;
            int d1 = params.d1;
            int d2 = params.d2;
            int d3 = params.d3;
            boolean sparse = params.sparse;
            this.params = params;

            if (params.polytype == ntruparameters.ternary_polynomial_type_product)
            {
                f = productformpolynomial.frombinary(is, n, d1, d2, d3 + 1, d3);
            }
            else
            {
                integerpolynomial fint = integerpolynomial.frombinary3tight(is, n);
                f = sparse ? new sparseternarypolynomial(fint) : new denseternarypolynomial(fint);
            }

            if (params.basistype == ntrusigningkeygenerationparameters.basis_type_standard)
            {
                integerpolynomial fprimeint = integerpolynomial.frombinary(is, n, q);
                for (int i = 0; i < fprimeint.coeffs.length; i++)
                {
                    fprimeint.coeffs[i] -= q / 2;
                }
                fprime = fprimeint;
            }
            else if (params.polytype == ntruparameters.ternary_polynomial_type_product)
            {
                fprime = productformpolynomial.frombinary(is, n, d1, d2, d3 + 1, d3);
            }
            else
            {
                fprime = integerpolynomial.frombinary3tight(is, n);
            }

            if (include_h)
            {
                h = integerpolynomial.frombinary(is, n, q);
            }
        }

        /**
         * writes the basis to an output stream
         *
         * @param os        an output stream
         * @param include_h whether to write the polynomial <code>h</code> (<code>true</code>) or only <code>f</code> and <code>f'</code> (<code>false</code>)
         * @throws ioexception
         */
        void encode(outputstream os, boolean include_h)
            throws ioexception
        {
            int q = params.q;

            os.write(getencoded(f));
            if (params.basistype == ntrusigningkeygenerationparameters.basis_type_standard)
            {
                integerpolynomial fprimeint = fprime.tointegerpolynomial();
                for (int i = 0; i < fprimeint.coeffs.length; i++)
                {
                    fprimeint.coeffs[i] += q / 2;
                }
                os.write(fprimeint.tobinary(q));
            }
            else
            {
                os.write(getencoded(fprime));
            }
            if (include_h)
            {
                os.write(h.tobinary(q));
            }
        }

        private byte[] getencoded(polynomial p)
        {
            if (p instanceof productformpolynomial)
            {
                return ((productformpolynomial)p).tobinary();
            }
            else
            {
                return p.tointegerpolynomial().tobinary3tight();
            }
        }

        @override
        public int hashcode()
        {
            final int prime = 31;
            int result = 1;
            result = prime * result + ((f == null) ? 0 : f.hashcode());
            result = prime * result + ((fprime == null) ? 0 : fprime.hashcode());
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
            if (!(obj instanceof basis))
            {
                return false;
            }
            basis other = (basis)obj;
            if (f == null)
            {
                if (other.f != null)
                {
                    return false;
                }
            }
            else if (!f.equals(other.f))
            {
                return false;
            }
            if (fprime == null)
            {
                if (other.fprime != null)
                {
                    return false;
                }
            }
            else if (!fprime.equals(other.fprime))
            {
                return false;
            }
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
}