package org.ripple.bouncycastle.pqc.crypto.mceliece;

import org.ripple.bouncycastle.pqc.math.linearalgebra.gf2matrix;

/**
 *
 *
 *
 */
public class mceliececca2publickeyparameters
    extends mceliececca2keyparameters
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
     * @param params mceliececca2parameters
     */
    public mceliececca2publickeyparameters(string oid, int n, int t, gf2matrix matrix, mceliececca2parameters params)
    {
        super(false, params);
        this.oid = oid;
        this.n = n;
        this.t = t;
        this.matrixg = new gf2matrix(matrix);
    }

    /**
     * constructor (used by {@link mceliecekeyfactory}).
     *
     * @param n         length of the code
     * @param t         error correction capability of the code
     * @param encmatrix encoded generator matrix
     * @param params    mceliececca2parameters
     */
    public mceliececca2publickeyparameters(string oid, int n, int t, byte[] encmatrix, mceliececca2parameters params)
    {
        super(false, params);
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

    /**
     * @return the dimension of the code
     */
    public int getk()
    {
        return matrixg.getnumrows();
    }

    public string getoidstring()
    {
        return oid;

    }
}
