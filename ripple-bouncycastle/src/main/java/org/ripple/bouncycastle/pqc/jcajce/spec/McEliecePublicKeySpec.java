package org.ripple.bouncycastle.pqc.jcajce.spec;


import java.security.spec.keyspec;

import org.ripple.bouncycastle.pqc.math.linearalgebra.gf2matrix;

/**
 * this class provides a specification for a mceliece public key.
 *
 * @see org.ripple.bouncycastle.pqc.jcajce.provider.mceliece.bcmceliecepublickey
 */
public class mceliecepublickeyspec
    implements keyspec
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
     * constructor (used by {@link org.ripple.bouncycastle.pqc.jcajce.provider.mceliece.mceliecekeyfactoryspi}).
     *
     * @param oid
     * @param n   the length of the code
     * @param t   the error correction capability of the code
     * @param g   the generator matrix
     */
    public mceliecepublickeyspec(string oid, int n, int t, gf2matrix g)
    {
        this.oid = oid;
        this.n = n;
        this.t = t;
        this.g = new gf2matrix(g);
    }

    /**
     * constructor (used by {@link org.ripple.bouncycastle.pqc.jcajce.provider.mceliece.mceliecekeyfactoryspi}).
     *
     * @param oid
     * @param n    the length of the code
     * @param t    the error correction capability of the code
     * @param encg the encoded generator matrix
     */
    public mceliecepublickeyspec(string oid, int t, int n, byte[] encg)
    {
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

}
