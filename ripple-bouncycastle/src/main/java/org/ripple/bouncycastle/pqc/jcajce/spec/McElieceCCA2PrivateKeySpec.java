package org.ripple.bouncycastle.pqc.jcajce.spec;

import java.security.spec.keyspec;

import org.ripple.bouncycastle.pqc.math.linearalgebra.gf2matrix;
import org.ripple.bouncycastle.pqc.math.linearalgebra.gf2mfield;
import org.ripple.bouncycastle.pqc.math.linearalgebra.permutation;
import org.ripple.bouncycastle.pqc.math.linearalgebra.polynomialgf2msmallm;

/**
 * this class provides a specification for a mceliece cca2 private key.
 *
 * @see jdkmceliececca2privatekey
 */
public class mceliececca2privatekeyspec
    implements keyspec
{

    // the oid of the algorithm
    private string oid;

    // the length of the code
    private int n;

    // the dimension of the code
    private int k;

    // the finte field gf(2^m)
    private gf2mfield field;

    // the irreducible goppa polynomial
    private polynomialgf2msmallm goppapoly;

    // the permutation
    private permutation p;

    // the canonical check matrix
    private gf2matrix h;

    // the matrix used to compute square roots in (gf(2^m))^t
    private polynomialgf2msmallm[] qinv;

    /**
     * constructor.
     *
     * @param n     the length of the code
     * @param k     the dimension of the code
     * @param field the finite field <tt>gf(2<sup>m</sup>)</tt>
     * @param gp    the irreducible goppa polynomial
     * @param p     the permutation
     * @param h     the canonical check matrix
     * @param qinv  the matrix used to compute square roots in
     *              <tt>(gf(2^m))^t</tt>
     */
    public mceliececca2privatekeyspec(string oid, int n, int k, gf2mfield field,
                                      polynomialgf2msmallm gp, permutation p, gf2matrix h,
                                      polynomialgf2msmallm[] qinv)
    {
        this.oid = oid;
        this.n = n;
        this.k = k;
        this.field = field;
        this.goppapoly = gp;
        this.p = p;
        this.h = h;
        this.qinv = qinv;
    }

    /**
     * constructor used by the {@link mceliecekeyfactory}.
     *
     * @param n            the length of the code
     * @param k            the dimension of the code
     * @param encfieldpoly the encoded field polynomial defining the finite field
     *                     <tt>gf(2<sup>m</sup>)</tt>
     * @param encgoppapoly the encoded irreducible goppa polynomial
     * @param encp         the encoded permutation
     * @param ench         the encoded canonical check matrix
     * @param encqinv      the encoded matrix used to compute square roots in
     *                     <tt>(gf(2^m))^t</tt>
     */
    public mceliececca2privatekeyspec(string oid, int n, int k, byte[] encfieldpoly,
                                      byte[] encgoppapoly, byte[] encp, byte[] ench, byte[][] encqinv)
    {
        this.oid = oid;
        this.n = n;
        this.k = k;
        field = new gf2mfield(encfieldpoly);
        goppapoly = new polynomialgf2msmallm(field, encgoppapoly);
        p = new permutation(encp);
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
     * @return the finite field
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
     * @return the permutation p
     */
    public permutation getp()
    {
        return p;
    }

    /**
     * @return the canonical check matrix h
     */
    public gf2matrix geth()
    {
        return h;
    }

    /**
     * @return the matrix used to compute square roots in <tt>(gf(2^m))^t</tt>
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
