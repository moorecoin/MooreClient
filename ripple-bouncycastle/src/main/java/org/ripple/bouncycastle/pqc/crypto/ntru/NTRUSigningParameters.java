package org.ripple.bouncycastle.pqc.crypto.ntru;

import java.io.datainputstream;
import java.io.dataoutputstream;
import java.io.ioexception;
import java.io.inputstream;
import java.io.outputstream;
import java.text.decimalformat;

import org.ripple.bouncycastle.crypto.digest;
import org.ripple.bouncycastle.crypto.digests.sha256digest;
import org.ripple.bouncycastle.crypto.digests.sha512digest;

/**
 * a set of parameters for ntrusign. several predefined parameter sets are available and new ones can be created as well.
 */
public class ntrusigningparameters
    implements cloneable
{
    public int n;
    public int q;
    public int d, d1, d2, d3, b;
    double beta;
    public double betasq;
    double normbound;
    public double normboundsq;
    public int signfailtolerance = 100;
    int bitsf = 6;   // max #bits needed to encode one coefficient of the polynomial f
    public digest hashalg;

    /**
     * constructs a parameter set that uses ternary private keys (i.e. </code>polytype=simple</code>).
     *
     * @param n            number of polynomial coefficients
     * @param q            modulus
     * @param d            number of -1's in the private polynomials <code>f</code> and <code>g</code>
     * @param b            number of perturbations
     * @param beta         balancing factor for the transpose lattice
     * @param normbound    maximum norm for valid signatures
     * @param hashalg      a valid identifier for a <code>java.security.messagedigest</code> instance such as <code>sha-256</code>. the <code>messagedigest</code> must support the <code>getdigestlength()</code> method.
     */
    public ntrusigningparameters(int n, int q, int d, int b, double beta, double normbound, digest hashalg)
    {
        this.n = n;
        this.q = q;
        this.d = d;
        this.b = b;
        this.beta = beta;
        this.normbound = normbound;
        this.hashalg = hashalg;
        init();
    }

    /**
     * constructs a parameter set that uses product-form private keys (i.e. </code>polytype=product</code>).
     *
     * @param n            number of polynomial coefficients
     * @param q            modulus
     * @param d1           number of -1's in the private polynomials <code>f</code> and <code>g</code>
     * @param d2           number of -1's in the private polynomials <code>f</code> and <code>g</code>
     * @param d3           number of -1's in the private polynomials <code>f</code> and <code>g</code>
     * @param b            number of perturbations
     * @param beta         balancing factor for the transpose lattice
     * @param normbound    maximum norm for valid signatures
     * @param keynormbound maximum norm for the ploynomials <code>f</code> and <code>g</code>
     * @param hashalg      a valid identifier for a <code>java.security.messagedigest</code> instance such as <code>sha-256</code>. the <code>messagedigest</code> must support the <code>getdigestlength()</code> method.
     */
    public ntrusigningparameters(int n, int q, int d1, int d2, int d3, int b, double beta, double normbound, double keynormbound, digest hashalg)
    {
        this.n = n;
        this.q = q;
        this.d1 = d1;
        this.d2 = d2;
        this.d3 = d3;
        this.b = b;
        this.beta = beta;
        this.normbound = normbound;
        this.hashalg = hashalg;
        init();
    }

    private void init()
    {
        betasq = beta * beta;
        normboundsq = normbound * normbound;
    }

    /**
     * reads a parameter set from an input stream.
     *
     * @param is an input stream
     * @throws ioexception
     */
    public ntrusigningparameters(inputstream is)
        throws ioexception
    {
        datainputstream dis = new datainputstream(is);
        n = dis.readint();
        q = dis.readint();
        d = dis.readint();
        d1 = dis.readint();
        d2 = dis.readint();
        d3 = dis.readint();
        b = dis.readint();
        beta = dis.readdouble();
        normbound = dis.readdouble();
        signfailtolerance = dis.readint();
        bitsf = dis.readint();
        string alg = dis.readutf();
        if ("sha-512".equals(alg))
        {
            hashalg = new sha512digest();
        }
        else if ("sha-256".equals(alg))
        {
            hashalg = new sha256digest();
        }
        init();
    }

    /**
     * writes the parameter set to an output stream
     *
     * @param os an output stream
     * @throws ioexception
     */
    public void writeto(outputstream os)
        throws ioexception
    {
        dataoutputstream dos = new dataoutputstream(os);
        dos.writeint(n);
        dos.writeint(q);
        dos.writeint(d);
        dos.writeint(d1);
        dos.writeint(d2);
        dos.writeint(d3);
        dos.writeint(b);
        dos.writedouble(beta);
        dos.writedouble(normbound);
        dos.writeint(signfailtolerance);
        dos.writeint(bitsf);
        dos.writeutf(hashalg.getalgorithmname());
    }

    public ntrusigningparameters clone()
    {
        return new ntrusigningparameters(n, q, d, b, beta, normbound, hashalg);
    }

    public int hashcode()
    {
        final int prime = 31;
        int result = 1;
        result = prime * result + b;
        result = prime * result + n;
        long temp;
        temp = double.doubletolongbits(beta);
        result = prime * result + (int)(temp ^ (temp >>> 32));
        temp = double.doubletolongbits(betasq);
        result = prime * result + (int)(temp ^ (temp >>> 32));
        result = prime * result + bitsf;
        result = prime * result + d;
        result = prime * result + d1;
        result = prime * result + d2;
        result = prime * result + d3;
        result = prime * result + ((hashalg == null) ? 0 : hashalg.getalgorithmname().hashcode());
        temp = double.doubletolongbits(normbound);
        result = prime * result + (int)(temp ^ (temp >>> 32));
        temp = double.doubletolongbits(normboundsq);
        result = prime * result + (int)(temp ^ (temp >>> 32));
        result = prime * result + q;
        result = prime * result + signfailtolerance;
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
        if (!(obj instanceof ntrusigningparameters))
        {
            return false;
        }
        ntrusigningparameters other = (ntrusigningparameters)obj;
        if (b != other.b)
        {
            return false;
        }
        if (n != other.n)
        {
            return false;
        }
        if (double.doubletolongbits(beta) != double.doubletolongbits(other.beta))
        {
            return false;
        }
        if (double.doubletolongbits(betasq) != double.doubletolongbits(other.betasq))
        {
            return false;
        }
        if (bitsf != other.bitsf)
        {
            return false;
        }
        if (d != other.d)
        {
            return false;
        }
        if (d1 != other.d1)
        {
            return false;
        }
        if (d2 != other.d2)
        {
            return false;
        }
        if (d3 != other.d3)
        {
            return false;
        }
        if (hashalg == null)
        {
            if (other.hashalg != null)
            {
                return false;
            }
        }
        else if (!hashalg.getalgorithmname().equals(other.hashalg.getalgorithmname()))
        {
            return false;
        }
        if (double.doubletolongbits(normbound) != double.doubletolongbits(other.normbound))
        {
            return false;
        }
        if (double.doubletolongbits(normboundsq) != double.doubletolongbits(other.normboundsq))
        {
            return false;
        }
        if (q != other.q)
        {
            return false;
        }
        if (signfailtolerance != other.signfailtolerance)
        {
            return false;
        }

        return true;
    }

    public string tostring()
    {
        decimalformat format = new decimalformat("0.00");

        stringbuilder output = new stringbuilder("signatureparameters(n=" + n + " q=" + q);

        output.append(" b=" + b + " beta=" + format.format(beta) +
            " normbound=" + format.format(normbound) +
            " hashalg=" + hashalg + ")");
        return output.tostring();
    }
}
