package org.ripple.bouncycastle.pqc.jcajce.spec;

import java.security.spec.keyspec;

import org.ripple.bouncycastle.pqc.math.linearalgebra.gf2matrix;


/**
 * this class provides a specification for a mceliece cca2 public key.
 *
 * @see org.ripple.bouncycastle.pqc.jcajce.provider.mceliece.bcmceliececca2publickey
 */
public class mceliececca2publickeyspec
    implements keyspec
{

    // the oid of the algorithm
    private string oid;

    // the length of the code
    private int n;

    // the error correction capability of the code
    private int t;

    // the generator matrix
    private gf2matrix matrixg;

    /**
     * constructor.
     *
     * @param n      length of the code
     * @param t      error correction capability
     * @param matrix generator matrix
     */
    public mceliececca2publickeyspec(string oid, int n, int t, gf2matrix matrix)
    {
        this.oid = oid;
        this.n = n;
        this.t = t;
        this.matrixg = new gf2matrix(matrix);
    }

    /**
     * constructor (used by {@link org.ripple.bouncycastle.pqc.jcajce.provider.mceliece.mceliecekeyfactoryspi}).
     *
     * @param n         length of the code
     * @param t         error correction capability of the code
     * @param encmatrix encoded generator matrix
     */
    public mceliececca2publickeyspec(string oid, int n, int t, byte[] encmatrix)
    {
        this.oid = oid;
        this.n = n;
        this.t = t;
        this.matrixg = new gf2matrix(encmatrix);
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
     * @return the generator matrix
     */
    public gf2matrix getmatrixg()
    {
        return matrixg;
    }

    public string getoidstring()
    {
        return oid;

    }
}
