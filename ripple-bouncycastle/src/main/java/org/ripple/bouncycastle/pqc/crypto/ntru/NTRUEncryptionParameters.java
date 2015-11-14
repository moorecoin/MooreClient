package org.ripple.bouncycastle.pqc.crypto.ntru;

import java.io.datainputstream;
import java.io.dataoutputstream;
import java.io.ioexception;
import java.io.inputstream;
import java.io.outputstream;
import java.util.arrays;

import org.ripple.bouncycastle.crypto.digest;
import org.ripple.bouncycastle.crypto.digests.sha256digest;
import org.ripple.bouncycastle.crypto.digests.sha512digest;

/**
 * a set of parameters for ntruencrypt. several predefined parameter sets are available and new ones can be created as well.
 */
public class ntruencryptionparameters
    implements cloneable
{

    public int n, q, df, df1, df2, df3;
    public int dr;
    public int dr1;
    public int dr2;
    public int dr3;
    public int dg;
    int llen;
    public int maxmsglenbytes;
    public int db;
    public int bufferlenbits;
    int bufferlentrits;
    public int dm0;
    public int pklen;
    public int c;
    public int mincallsr;
    public int mincallsmask;
    public boolean hashseed;
    public byte[] oid;
    public boolean sparse;
    public boolean fastfp;
    public int polytype;
    public digest hashalg;

    /**
     * constructs a parameter set that uses ternary private keys (i.e. </code>polytype=simple</code>).
     *
     * @param n            number of polynomial coefficients
     * @param q            modulus
     * @param df           number of ones in the private polynomial <code>f</code>
     * @param dm0          minimum acceptable number of -1's, 0's, and 1's in the polynomial <code>m'</code> in the last encryption step
     * @param db           number of random bits to prepend to the message
     * @param c            a parameter for the index generation function ({@link org.ripple.bouncycastle.pqc.crypto.ntru.indexgenerator})
     * @param mincallsr    minimum number of hash calls for the igf to make
     * @param mincallsmask minimum number of calls to generate the masking polynomial
     * @param hashseed     whether to hash the seed in the mgf first (true) or use the seed directly (false)
     * @param oid          three bytes that uniquely identify the parameter set
     * @param sparse       whether to treat ternary polynomials as sparsely populated ({@link org.ripple.bouncycastle.pqc.math.ntru.polynomial.sparseternarypolynomial} vs {@link org.ripple.bouncycastle.pqc.math.ntru.polynomial.denseternarypolynomial})
     * @param fastfp       whether <code>f=1+p*f</code> for a ternary <code>f</code> (true) or <code>f</code> is ternary (false)
     * @param hashalg      a valid identifier for a <code>java.security.messagedigest</code> instance such as <code>sha-256</code>. the <code>messagedigest</code> must support the <code>getdigestlength()</code> method.
     */
    public ntruencryptionparameters(int n, int q, int df, int dm0, int db, int c, int mincallsr, int mincallsmask, boolean hashseed, byte[] oid, boolean sparse, boolean fastfp, digest hashalg)
    {
        this.n = n;
        this.q = q;
        this.df = df;
        this.db = db;
        this.dm0 = dm0;
        this.c = c;
        this.mincallsr = mincallsr;
        this.mincallsmask = mincallsmask;
        this.hashseed = hashseed;
        this.oid = oid;
        this.sparse = sparse;
        this.fastfp = fastfp;
        this.polytype = ntruparameters.ternary_polynomial_type_simple;
        this.hashalg = hashalg;
        init();
    }

    /**
     * constructs a parameter set that uses product-form private keys (i.e. </code>polytype=product</code>).
     *
     * @param n            number of polynomial coefficients
     * @param q            modulus
     * @param df1          number of ones in the private polynomial <code>f1</code>
     * @param df2          number of ones in the private polynomial <code>f2</code>
     * @param df3          number of ones in the private polynomial <code>f3</code>
     * @param dm0          minimum acceptable number of -1's, 0's, and 1's in the polynomial <code>m'</code> in the last encryption step
     * @param db           number of random bits to prepend to the message
     * @param c            a parameter for the index generation function ({@link  org.ripple.bouncycastle.pqc.crypto.ntru.indexgenerator})
     * @param mincallsr    minimum number of hash calls for the igf to make
     * @param mincallsmask minimum number of calls to generate the masking polynomial
     * @param hashseed     whether to hash the seed in the mgf first (true) or use the seed directly (false)
     * @param oid          three bytes that uniquely identify the parameter set
     * @param sparse       whether to treat ternary polynomials as sparsely populated ({@link org.ripple.bouncycastle.pqc.math.ntru.polynomial.sparseternarypolynomial} vs {@link org.ripple.bouncycastle.pqc.math.ntru.polynomial.denseternarypolynomial})
     * @param fastfp       whether <code>f=1+p*f</code> for a ternary <code>f</code> (true) or <code>f</code> is ternary (false)
     * @param hashalg      a valid identifier for a <code>java.security.messagedigest</code> instance such as <code>sha-256</code>
     */
    public ntruencryptionparameters(int n, int q, int df1, int df2, int df3, int dm0, int db, int c, int mincallsr, int mincallsmask, boolean hashseed, byte[] oid, boolean sparse, boolean fastfp, digest hashalg)
    {
        this.n = n;
        this.q = q;
        this.df1 = df1;
        this.df2 = df2;
        this.df3 = df3;
        this.db = db;
        this.dm0 = dm0;
        this.c = c;
        this.mincallsr = mincallsr;
        this.mincallsmask = mincallsmask;
        this.hashseed = hashseed;
        this.oid = oid;
        this.sparse = sparse;
        this.fastfp = fastfp;
        this.polytype = ntruparameters.ternary_polynomial_type_product;
        this.hashalg = hashalg;
        init();
    }

    private void init()
    {
        dr = df;
        dr1 = df1;
        dr2 = df2;
        dr3 = df3;
        dg = n / 3;
        llen = 1;   // ceil(log2(maxmsglenbytes))
        maxmsglenbytes = n * 3 / 2 / 8 - llen - db / 8 - 1;
        bufferlenbits = (n * 3 / 2 + 7) / 8 * 8 + 1;
        bufferlentrits = n - 1;
        pklen = db;
    }

    /**
     * reads a parameter set from an input stream.
     *
     * @param is an input stream
     * @throws ioexception
     */
    public ntruencryptionparameters(inputstream is)
        throws ioexception
    {
        datainputstream dis = new datainputstream(is);
        n = dis.readint();
        q = dis.readint();
        df = dis.readint();
        df1 = dis.readint();
        df2 = dis.readint();
        df3 = dis.readint();
        db = dis.readint();
        dm0 = dis.readint();
        c = dis.readint();
        mincallsr = dis.readint();
        mincallsmask = dis.readint();
        hashseed = dis.readboolean();
        oid = new byte[3];
        dis.read(oid);
        sparse = dis.readboolean();
        fastfp = dis.readboolean();
        polytype = dis.read();

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

    public ntruencryptionparameters clone()
    {
        if (polytype == ntruparameters.ternary_polynomial_type_simple)
        {
            return new ntruencryptionparameters(n, q, df, dm0, db, c, mincallsr, mincallsmask, hashseed, oid, sparse, fastfp, hashalg);
        }
        else
        {
            return new ntruencryptionparameters(n, q, df1, df2, df3, dm0, db, c, mincallsr, mincallsmask, hashseed, oid, sparse, fastfp, hashalg);
        }
    }

    /**
     * returns the maximum length a plaintext message can be with this parameter set.
     *
     * @return the maximum length in bytes
     */
    public int getmaxmessagelength()
    {
        return maxmsglenbytes;
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
        dos.writeint(df);
        dos.writeint(df1);
        dos.writeint(df2);
        dos.writeint(df3);
        dos.writeint(db);
        dos.writeint(dm0);
        dos.writeint(c);
        dos.writeint(mincallsr);
        dos.writeint(mincallsmask);
        dos.writeboolean(hashseed);
        dos.write(oid);
        dos.writeboolean(sparse);
        dos.writeboolean(fastfp);
        dos.write(polytype);
        dos.writeutf(hashalg.getalgorithmname());
    }


    public int hashcode()
    {
        final int prime = 31;
        int result = 1;
        result = prime * result + n;
        result = prime * result + bufferlenbits;
        result = prime * result + bufferlentrits;
        result = prime * result + c;
        result = prime * result + db;
        result = prime * result + df;
        result = prime * result + df1;
        result = prime * result + df2;
        result = prime * result + df3;
        result = prime * result + dg;
        result = prime * result + dm0;
        result = prime * result + dr;
        result = prime * result + dr1;
        result = prime * result + dr2;
        result = prime * result + dr3;
        result = prime * result + (fastfp ? 1231 : 1237);
        result = prime * result + ((hashalg == null) ? 0 : hashalg.getalgorithmname().hashcode());
        result = prime * result + (hashseed ? 1231 : 1237);
        result = prime * result + llen;
        result = prime * result + maxmsglenbytes;
        result = prime * result + mincallsmask;
        result = prime * result + mincallsr;
        result = prime * result + arrays.hashcode(oid);
        result = prime * result + pklen;
        result = prime * result + polytype;
        result = prime * result + q;
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
        if (getclass() != obj.getclass())
        {
            return false;
        }
        ntruencryptionparameters other = (ntruencryptionparameters)obj;
        if (n != other.n)
        {
            return false;
        }
        if (bufferlenbits != other.bufferlenbits)
        {
            return false;
        }
        if (bufferlentrits != other.bufferlentrits)
        {
            return false;
        }
        if (c != other.c)
        {
            return false;
        }
        if (db != other.db)
        {
            return false;
        }
        if (df != other.df)
        {
            return false;
        }
        if (df1 != other.df1)
        {
            return false;
        }
        if (df2 != other.df2)
        {
            return false;
        }
        if (df3 != other.df3)
        {
            return false;
        }
        if (dg != other.dg)
        {
            return false;
        }
        if (dm0 != other.dm0)
        {
            return false;
        }
        if (dr != other.dr)
        {
            return false;
        }
        if (dr1 != other.dr1)
        {
            return false;
        }
        if (dr2 != other.dr2)
        {
            return false;
        }
        if (dr3 != other.dr3)
        {
            return false;
        }
        if (fastfp != other.fastfp)
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
        if (hashseed != other.hashseed)
        {
            return false;
        }
        if (llen != other.llen)
        {
            return false;
        }
        if (maxmsglenbytes != other.maxmsglenbytes)
        {
            return false;
        }
        if (mincallsmask != other.mincallsmask)
        {
            return false;
        }
        if (mincallsr != other.mincallsr)
        {
            return false;
        }
        if (!arrays.equals(oid, other.oid))
        {
            return false;
        }
        if (pklen != other.pklen)
        {
            return false;
        }
        if (polytype != other.polytype)
        {
            return false;
        }
        if (q != other.q)
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
        stringbuilder output = new stringbuilder("encryptionparameters(n=" + n + " q=" + q);
        if (polytype == ntruparameters.ternary_polynomial_type_simple)
        {
            output.append(" polytype=simple df=" + df);
        }
        else
        {
            output.append(" polytype=product df1=" + df1 + " df2=" + df2 + " df3=" + df3);
        }
        output.append(" dm0=" + dm0 + " db=" + db + " c=" + c + " mincallsr=" + mincallsr + " mincallsmask=" + mincallsmask +
            " hashseed=" + hashseed + " hashalg=" + hashalg + " oid=" + arrays.tostring(oid) + " sparse=" + sparse + ")");
        return output.tostring();
    }
}
