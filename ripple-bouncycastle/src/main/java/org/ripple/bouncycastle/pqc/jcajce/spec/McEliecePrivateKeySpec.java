package org.ripple.bouncycastle.pqc.jcajce.spec;


import java.security.spec.keyspec;

import org.ripple.bouncycastle.pqc.math.linearalgebra.gf2matrix;
import org.ripple.bouncycastle.pqc.math.linearalgebra.gf2mfield;
import org.ripple.bouncycastle.pqc.math.linearalgebra.permutation;
import org.ripple.bouncycastle.pqc.math.linearalgebra.polynomialgf2msmallm;

/**
 * this class provides a specification for a mceliece private key.
 *
 * @see org.bouncycastle.pqc.ecc.jdkmcelieceprivatekey.mcelieceprivatekey
 * @see keyspec
 */
public class mcelieceprivatekeyspec
    implements keyspec
{

    // the oid of the algorithm
    private string oid;

    // the length of the code
    private int n;

    // the dimension of the code, where <tt>k &gt;= n - mt</tt>
    private int k;

    // the underlying finite field
    private gf2mfield field;

    // the irreducible goppa polynomial
    private polynomialgf2msmallm goppapoly;

    // a k x k random binary non-singular matrix
    private gf2matrix sinv;

    // the permutation used to generate the systematic check matrix
    private permutation p1;

    // the permutation used to compute the public generator matrix
    private permutation p2;

    // the canonical check matrix of the code
    private gf2matrix h;

    // the matrix used to compute square roots in <tt>(gf(2^m))^t</tt>
    private polynomialgf2msmallm[] qinv;

    /**
     * constructor.
     *
     * @param oid
     * @param n         the length of the code
     * @param k         the dimension of the code
     * @param field     the field polynomial defining the finite field
     *                  <tt>gf(2<sup>m</sup>)</tt>
     * @param goppapoly the irreducible goppa polynomial
     * @param sinv      the matrix <tt>s<sup>-1</sup></tt>
     * @param p1        the permutation used to generate the systematic check
     *                  matrix
     * @param p2        the permutation used to compute the public generator
     *                  matrix
     * @param h         the canonical check matrix
     * @param qinv      the matrix used to compute square roots in
     *                  <tt>(gf(2<sup>m</sup>))<sup>t</sup></tt>
     */
    public mcelieceprivatekeyspec(string oid, int n, int k, gf2mfield field,
                                  polynomialgf2msmallm goppapoly, gf2matrix sinv, permutation p1,
                                  permutation p2, gf2matrix h, polynomialgf2msmallm[] qinv)
    {
        this.oid = oid;
        this.k = k;
        this.n = n;
        this.field = field;
        this.goppapoly = goppapoly;
        this.sinv = sinv;
        this.p1 = p1;
        this.p2 = p2;
        this.h = h;
        this.qinv = qinv;
    }

    /**
     * constructor (used by the {@link mceliecekeyfactory}).
     *
     * @param oid
     * @param n            the length of the code
     * @param k            the dimension of the code
     * @param encfield     the encoded field polynomial defining the finite field
     *                     <tt>gf(2<sup>m</sup>)</tt>
     * @param encgoppapoly the encoded irreducible goppa polynomial
     * @param encsinv      the encoded matrix <tt>s<sup>-1</sup></tt>
     * @param encp1        the encoded permutation used to generate the systematic
     *                     check matrix
     * @param encp2        the encoded permutation used to compute the public
     *                     generator matrix
     * @param ench         the encoded canonical check matrix
     * @param encqinv      the encoded matrix used to compute square roots in
     *                     <tt>(gf(2<sup>m</sup>))<sup>t</sup></tt>
     */
    public mcelieceprivatekeyspec(string oid, int n, int k, byte[] encfield,
                                  byte[] encgoppapoly, byte[] encsinv, byte[] encp1, byte[] encp2,
                                  byte[] ench, byte[][] encqinv)
    {
        this.oid = oid;
        this.n = n;
        this.k = k;
        field = new gf2mfield(encfield);
        goppapoly = new polynomialgf2msmallm(field, encgoppapoly);
        sinv = new gf2matrix(encsinv);
        p1 = new permutation(encp1);
        p2 = new permutation(encp2);
        h = new gf2matrix(ench);
        qinv = new polynomialgf2msmallm[encqinv.length];
        for (int i = 0; i < encqinv.length; i++)
        {
            qinv[i] = new polynomialgf2msmallm(field, encqinv[i]);
        }
    }

    /**
     * @return the length of the code
     */
    public int getn()
    {
        return n;
    }

    /**
     * @return the dimension of the code
     */
    public int getk()
    {
        return k;
    }

    /**
     * @return the finite field <tt>gf(2<sup>m</sup>)</tt>
     */
    public gf2mfield getfield()
    {
        return field;
    }

    /**
     * @return the irreducible goppa polynomial
     */
    public polynomialgf2msmallm getgoppapoly()
    {
        return goppapoly;
    }

    /**
     * @return the k x k random binary non-singular matrix s^-1
     */
    public gf2matrix getsinv()
    {
        return sinv;
    }

    /**
     * @return the permutation used to generate the systematic check matrix
     */
    public permutation getp1()
    {
        return p1;
    }

    /**
     * @return the permutation used to compute the public generator matrix
     */
    public permutation getp2()
    {
        return p2;
    }

    /**
     * @return the canonical check matrix h
     */
    public gf2matrix geth()
    {
        return h;
    }

    /**
     * @return the matrix used to compute square roots in
     *         <tt>(gf(2<sup>m</sup>))<sup>t</sup></tt>
     */
    public polynomialgf2msmallm[] getqinv()
    {
        return qinv;
    }

    public string getoidstring()
    {
        return oid;
    }

}
