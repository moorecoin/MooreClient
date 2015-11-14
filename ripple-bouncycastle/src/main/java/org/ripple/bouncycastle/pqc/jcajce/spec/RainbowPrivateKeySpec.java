package org.ripple.bouncycastle.pqc.jcajce.spec;

import java.security.spec.keyspec;

import org.ripple.bouncycastle.pqc.crypto.rainbow.layer;

/**
 * this class provides a specification for a rainbowsignature private key.
 *
 * @see keyspec
 */
public class rainbowprivatekeyspec
    implements keyspec
{
    /*
      * invertible affine linear map l1
      */
    // the inverse of a1, (n-v1 x n-v1 matrix)
    private short[][] a1inv;

    // translation vector of l1
    private short[] b1;

    /*
      * invertible affine linear map l2
      */
    // the inverse of a2, (n x n matrix)
    private short[][] a2inv;

    // translation vector of l2
    private short[] b2;

    /*
      * components of f
      */
    // the number of vinegar-variables per layer.
    private int[] vi;

    // contains the polynomials with their coefficients of private map f
    private layer[] layers;

    /**
     * constructor
     *
     * @param a1inv  the inverse of a1(the matrix part of the affine linear map l1)
     *               (n-v1 x n-v1 matrix)
     * @param b1     translation vector, part of the linear affine map l1
     * @param a2inv  the inverse of a2(the matrix part of the affine linear map l2)
     *               (n x n matrix)
     * @param b2     translation vector, part of the linear affine map l2
     * @param vi     the number of vinegar-variables per layer
     * @param layers the polynomials with their coefficients of private map f
     */
    public rainbowprivatekeyspec(short[][] a1inv, short[] b1,
                                 short[][] a2inv, short[] b2, int[] vi, layer[] layers)
    {
        this.a1inv = a1inv;
        this.b1 = b1;
        this.a2inv = a2inv;
        this.b2 = b2;
        this.vi = vi;
        this.layers = layers;
    }

    /**
     * getter for the translation part of the private quadratic map l1.
     *
     * @return b1 the translation part of l1
     */
    public short[] getb1()
    {
        return this.b1;
    }

    /**
     * getter for the inverse matrix of a1.
     *
     * @return the a1inv inverse
     */
    public short[][] getinva1()
    {
        return this.a1inv;
    }

    /**
     * getter for the translation part of the private quadratic map l2.
     *
     * @return b2 the translation part of l2
     */
    public short[] getb2()
    {
        return this.b2;
    }

    /**
     * getter for the inverse matrix of a2
     *
     * @return the a2inv
     */
    public short[][] getinva2()
    {
        return this.a2inv;
    }

    /**
     * returns the layers contained in the private key
     *
     * @return layers
     */
    public layer[] getlayers()
    {
        return this.layers;
    }

    /**
     * /** returns the array of vi-s
     *
     * @return the vi
     */
    public int[] getvi()
    {
        return vi;
    }

}
