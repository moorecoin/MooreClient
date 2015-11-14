package org.ripple.bouncycastle.pqc.crypto.mceliece;

import org.ripple.bouncycastle.pqc.math.linearalgebra.gf2matrix;


public class mceliecepublickeyparameters
    extends mceliecekeyparameters
{

    // the oid of the algorithm
    private string oid;

    // the length of the code
    private int n;

    // the error correction capability of the code
    private int t;

    // the generator matrix
    private gf2matrix g;

    /**
     * constructor (used by {@link mceliecekeyfactory}).
     *
     * @param oid
     * @param n      the length of the code
     * @param t      the error correction capability of the code
     * @param g      the generator matrix
     * @param params mcelieceparameters
     */
    public mceliecepublickeyparameters(string oid, int n, int t, gf2matrix g, mcelieceparameters params)
    {
        super(false, params);
        this.oid = oid;
        this.n = n;
        this.t = t;
        this.g = new gf2matrix(g);
    }

    /**
     * constructor (used by {@link mceliecekeyfactory}).
     *
     * @param oid
     * @param n      the length of the code
     * @param t      the error correction capability of the code
     * @param encg   the encoded generator matrix
     * @param params mcelieceparameters
     */
    public mceliecepublickeyparameters(string oid, int t, int n, byte[] encg, mcelieceparameters params)
    {
        super(false, params);
        this.oid = oid;
        this.n = n;
        this.t = t;
        this.g = new gf2matrix(encg);
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
    public gf2matrix getg()
    {
        return g;
    }

    public string getoidstring()
    {
        return oid;

    }

    /**
     * @return the dimension of the code
     */
    public int getk()
    {
        return g.getnumrows();
    }

}
