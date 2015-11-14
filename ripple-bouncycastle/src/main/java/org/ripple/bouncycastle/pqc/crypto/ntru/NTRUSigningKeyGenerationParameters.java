package org.ripple.bouncycastle.pqc.crypto.ntru;

import java.io.datainputstream;
import java.io.dataoutputstream;
import java.io.ioexception;
import java.io.inputstream;
import java.io.outputstream;
import java.security.securerandom;
import java.text.decimalformat;

import org.ripple.bouncycastle.crypto.digest;
import org.ripple.bouncycastle.crypto.keygenerationparameters;
import org.ripple.bouncycastle.crypto.digests.sha256digest;
import org.ripple.bouncycastle.crypto.digests.sha512digest;

/**
 * a set of parameters for ntrusign. several predefined parameter sets are available and new ones can be created as well.
 */
public class ntrusigningkeygenerationparameters
    extends keygenerationparameters
    implements cloneable
{   
    public static final int basis_type_standard = 0;
    public static final int basis_type_transpose = 1;

    public static final int key_gen_alg_resultant = 0;
    public static final int key_gen_alg_float = 1;
    
    /**
     * gives 128 bits of security
     */
    public static final ntrusigningkeygenerationparameters apr2011_439 = new ntrusigningkeygenerationparameters(439, 2048, 146, 1, basis_type_transpose, 0.165, 400, 280, false, true, key_gen_alg_resultant, new sha256digest());

    /**
     * like <code>apr2011_439</code>, this parameter set gives 128 bits of security but uses product-form polynomials
     */
    public static final ntrusigningkeygenerationparameters apr2011_439_prod = new ntrusigningkeygenerationparameters(439, 2048, 9, 8, 5, 1, basis_type_transpose, 0.165, 400, 280, false, true, key_gen_alg_resultant, new sha256digest());

    /**
     * gives 256 bits of security
     */
    public static final ntrusigningkeygenerationparameters apr2011_743 = new ntrusigningkeygenerationparameters(743, 2048, 248, 1, basis_type_transpose, 0.127, 405, 360, true, false, key_gen_alg_resultant, new sha512digest());

    /**
     * like <code>apr2011_439</code>, this parameter set gives 256 bits of security but uses product-form polynomials
     */
    public static final ntrusigningkeygenerationparameters apr2011_743_prod = new ntrusigningkeygenerationparameters(743, 2048, 11, 11, 15, 1, basis_type_transpose, 0.127, 405, 360, true, false, key_gen_alg_resultant, new sha512digest());

    /**
     * generates key pairs quickly. use for testing only.
     */
    public static final ntrusigningkeygenerationparameters test157 = new ntrusigningkeygenerationparameters(157, 256, 29, 1, basis_type_transpose, 0.38, 200, 80, false, false, key_gen_alg_resultant, new sha256digest());
    /**
     * generates key pairs quickly. use for testing only.
     */
    public static final ntrusigningkeygenerationparameters test157_prod = new ntrusigningkeygenerationparameters(157, 256, 5, 5, 8, 1, basis_type_transpose, 0.38, 200, 80, false, false, key_gen_alg_resultant, new sha256digest());


    public int n;
    public int q;
    public int d, d1, d2, d3, b;
    double beta;
    public double betasq;
    double normbound;
    public double normboundsq;
    public int signfailtolerance = 100;
    double keynormbound;
    public double keynormboundsq;
    public boolean primecheck;   // true if n and 2n+1 are prime
    public int basistype;
    int bitsf = 6;   // max #bits needed to encode one coefficient of the polynomial f
    public boolean sparse;   // whether to treat ternary polynomials as sparsely populated
    public int keygenalg;
    public digest hashalg;
    public int polytype;

    /**
     * constructs a parameter set that uses ternary private keys (i.e. </code>polytype=simple</code>).
     *
     * @param n            number of polynomial coefficients
     * @param q            modulus
     * @param d            number of -1's in the private polynomials <code>f</code> and <code>g</code>
     * @param b            number of perturbations
     * @param basistype    whether to use the standard or transpose lattice
     * @param beta         balancing factor for the transpose lattice
     * @param normbound    maximum norm for valid signatures
     * @param keynormbound maximum norm for the ploynomials <code>f</code> and <code>g</code>
     * @param primecheck   whether <code>2n+1</code> is prime
     * @param sparse       whether to treat ternary polynomials as sparsely populated ({@link org.ripple.bouncycastle.pqc.math.ntru.polynomial.sparseternarypolynomial} vs {@link org.ripple.bouncycastle.pqc.math.ntru.polynomial.denseternarypolynomial})
     * @param keygenalg    <code>resultant</code> produces better bases, <code>float</code> is slightly faster. <code>resultant</code> follows the eess standard while <code>float</code> is described in hoffstein et al: an introduction to mathematical cryptography.
     * @param hashalg      a valid identifier for a <code>java.security.messagedigest</code> instance such as <code>sha-256</code>. the <code>messagedigest</code> must support the <code>getdigestlength()</code> method.
     */
    public ntrusigningkeygenerationparameters(int n, int q, int d, int b, int basistype, double beta, double normbound, double keynormbound, boolean primecheck, boolean sparse, int keygenalg, digest hashalg)
    {
        super(new securerandom(), n);
        this.n = n;
        this.q = q;
        this.d = d;
        this.b = b;
        this.basistype = basistype;
        this.beta = beta;
        this.normbound = normbound;
        this.keynormbound = keynormbound;
        this.primecheck = primecheck;
        this.sparse = sparse;
        this.keygenalg = keygenalg;
        this.hashalg = hashalg;
        polytype = ntruparameters.ternary_polynomial_type_simple;
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
     * @param basistype    whether to use the standard or transpose lattice
     * @param beta         balancing factor for the transpose lattice
     * @param normbound    maximum norm for valid signatures
     * @param keynormbound maximum norm for the ploynomials <code>f</code> and <code>g</code>
     * @param primecheck   whether <code>2n+1</code> is prime
     * @param sparse       whether to treat ternary polynomials as sparsely populated ({@link org.ripple.bouncycastle.pqc.math.ntru.polynomial.sparseternarypolynomial} vs {@link org.ripple.bouncycastle.pqc.math.ntru.polynomial.denseternarypolynomial})
     * @param keygenalg    <code>resultant</code> produces better bases, <code>float</code> is slightly faster. <code>resultant</code> follows the eess standard while <code>float</code> is described in hoffstein et al: an introduction to mathematical cryptography.
     * @param hashalg      a valid identifier for a <code>java.security.messagedigest</code> instance such as <code>sha-256</code>. the <code>messagedigest</code> must support the <code>getdigestlength()</code> method.
     */
    public ntrusigningkeygenerationparameters(int n, int q, int d1, int d2, int d3, int b, int basistype, double beta, double normbound, double keynormbound, boolean primecheck, boolean sparse, int keygenalg, digest hashalg)
    {
        super(new securerandom(), n);
        this.n = n;
        this.q = q;
        this.d1 = d1;
        this.d2 = d2;
        this.d3 = d3;
        this.b = b;
        this.basistype = basistype;
        this.beta = beta;
        this.normbound = normbound;
        this.keynormbound = keynormbound;
        this.primecheck = primecheck;
        this.sparse = sparse;
        this.keygenalg = keygenalg;
        this.hashalg = hashalg;
        polytype = ntruparameters.ternary_polynomial_type_product;
        init();
    }

    private void init()
    {
        betasq = beta * beta;
        normboundsq = normbound * normbound;
        keynormboundsq = keynormbound * keynormbound;
    }

    /**
     * reads a parameter set from an input stream.
     *
     * @param is an input stream
     * @throws java.io.ioexception
     */
    public ntrusigningkeygenerationparameters(inputstream is)
        throws ioexception
    {
        super(new securerandom(), 0);     // todo:
        datainputstream dis = new datainputstream(is);
        n = dis.readint();
        q = dis.readint();
        d = dis.readint();
        d1 = dis.readint();
        d2 = dis.readint();
        d3 = dis.readint();
        b = dis.readint();
        basistype = dis.readint();
        beta = dis.readdouble();
        normbound = dis.readdouble();
        keynormbound = dis.readdouble();
        signfailtolerance = dis.readint();
        primecheck = dis.readboolean();
        sparse = dis.readboolean();
        bitsf = dis.readint();
        keygenalg = dis.read();
        string alg = dis.readutf();
        if ("sha-512".equals(alg))
        {
            hashalg = new sha512digest();
        }
        else if ("sha-256".equals(alg))
        {
            hashalg = new sha256digest();
        }
        polytype = dis.read();
        init();
    }

    /**
     * writes the parameter set to an output stream
     *
     * @param os an output stream
     * @throws java.io.ioexception
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
        dos.writeint(basistype);
        dos.writedouble(beta);
        dos.writedouble(normbound);
        dos.writedouble(keynormbound);
        dos.writeint(signfailtolerance);
        dos.writeboolean(primecheck);
        dos.writeboolean(sparse);
        dos.writeint(bitsf);
        dos.write(keygenalg);
        dos.writeutf(hashalg.getalgorithmname());
        dos.write(polytype);
    }

    public ntrusigningparameters getsigningparameters()
    {
        return new ntrusigningparameters(n, q, d, b, beta, normbound, hashalg);
    }

    public ntrusigningkeygenerationparameters clone()
    {
        if (polytype == ntruparameters.ternary_polynomial_type_simple)
        {
            return new ntrusigningkeygenerationparameters(n, q, d, b, basistype, beta, normbound, keynormbound, primecheck, sparse, keygenalg, hashalg);
        }
        else
        {
            return new ntrusigningkeygenerationparameters(n, q, d1, d2, d3, b, basistype, beta, normbound, keynormbound, primecheck, sparse, keygenalg, hashalg);
        }
    }

    public int hashcode()
    {
        final int prime = 31;
        int result = 1;
        result = prime * result + b;
        result = prime * result + n;
        result = prime * result + basistype;
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
        result = prime * result + keygenalg;
        temp = double.doubletolongbits(keynormbound);
        result = prime * result + (int)(temp ^ (temp >>> 32));
        temp = double.doubletolongbits(keynormboundsq);
        result = prime * result + (int)(temp ^ (temp >>> 32));
        temp = double.doubletolongbits(normbound);
        result = prime * result + (int)(temp ^ (temp >>> 32));
        temp = double.doubletolongbits(normboundsq);
        result = prime * result + (int)(temp ^ (temp >>> 32));
        result = prime * result + polytype;
        result = prime * result + (primecheck ? 1231 : 1237);
        result = prime * result + q;
        result = prime * result + signfailtolerance;
        result = prime * result + (sparse ? 1231 : 1237);
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
        if (!(obj instanceof ntrusigningkeygenerationparameters))
        {
            return false;
        }
        ntrusigningkeygenerationparameters other = (ntrusigningkeygenerationparameters)obj;
        if (b != other.b)
        {
            return false;
        }
        if (n != other.n)
        {
            return false;
        }
        if (basistype != other.basistype)
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
        if (keygenalg != other.keygenalg)
        {
            return false;
        }
        if (double.doubletolongbits(keynormbound) != double.doubletolongbits(other.keynormbound))
        {
            return false;
        }
        if (double.doubletolongbits(keynormboundsq) != double.doubletolongbits(other.keynormboundsq))
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
        if (polytype != other.polytype)
        {
            return false;
        }
        if (primecheck != other.primecheck)
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
        if (sparse != other.sparse)
        {
            return false;
        }
        return true;
    }

    public string tostring()
    {
        decimalformat format = new decimalformat("0.00");

        stringbuilder output = new stringbuilder("signatureparameters(n=" + n + " q=" + q);
        if (polytype == ntruparameters.ternary_polynomial_type_simple)
        {
            output.append(" polytype=simple d=" + d);
        }
        else
        {
            output.append(" polytype=product d1=" + d1 + " d2=" + d2 + " d3=" + d3);
        }
        output.append(" b=" + b + " basistype=" + basistype + " beta=" + format.format(beta) +
            " normbound=" + format.format(normbound) + " keynormbound=" + format.format(keynormbound) +
            " prime=" + primecheck + " sparse=" + sparse + " keygenalg=" + keygenalg + " hashalg=" + hashalg + ")");
        return output.tostring();
    }
}
