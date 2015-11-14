package org.ripple.bouncycastle.pqc.jcajce.provider.rainbow;

import java.io.ioexception;
import java.security.privatekey;
import java.util.arrays;

import org.ripple.bouncycastle.asn1.dernull;
import org.ripple.bouncycastle.asn1.pkcs.privatekeyinfo;
import org.ripple.bouncycastle.asn1.x509.algorithmidentifier;
import org.ripple.bouncycastle.pqc.asn1.pqcobjectidentifiers;
import org.ripple.bouncycastle.pqc.asn1.rainbowprivatekey;
import org.ripple.bouncycastle.pqc.crypto.rainbow.layer;
import org.ripple.bouncycastle.pqc.crypto.rainbow.rainbowprivatekeyparameters;
import org.ripple.bouncycastle.pqc.crypto.rainbow.util.rainbowutil;
import org.ripple.bouncycastle.pqc.jcajce.spec.rainbowprivatekeyspec;

/**
 * the private key in rainbow consists of the linear affine maps l1, l2 and the
 * map f, consisting of quadratic polynomials. in this implementation, we
 * denote: l1 = a1*x + b1 l2 = a2*x + b2
 * <p/>
 * the coefficients of the polynomials in f are stored in 3-dimensional arrays
 * per layer. the indices of these arrays denote the polynomial, and the
 * variables.
 * <p/>
 * more detailed information about the private key is to be found in the paper
 * of jintai ding, dieter schmidt: rainbow, a new multivariable polynomial
 * signature scheme. acns 2005: 164-175 (http://dx.doi.org/10.1007/11496137_12)
 */
public class bcrainbowprivatekey
    implements privatekey
{
    private static final long serialversionuid = 1l;

    // the inverse of l1
    private short[][] a1inv;

    // translation vector element of l1
    private short[] b1;

    // the inverse of l2
    private short[][] a2inv;

    // translation vector of l2
    private short[] b2;

    /*
      * components of f
      */
    private layer[] layers;

    // set of vinegar vars per layer.
    private int[] vi;


    /**
     * constructor.
     *
     * @param a1inv
     * @param b1
     * @param a2inv
     * @param b2
     * @param layers
     */
    public bcrainbowprivatekey(short[][] a1inv, short[] b1, short[][] a2inv,
                               short[] b2, int[] vi, layer[] layers)
    {
        this.a1inv = a1inv;
        this.b1 = b1;
        this.a2inv = a2inv;
        this.b2 = b2;
        this.vi = vi;
        this.layers = layers;
    }

    /**
     * constructor (used by the {@link rainbowkeyfactoryspi}).
     *
     * @param keyspec a {@link rainbowprivatekeyspec}
     */
    public bcrainbowprivatekey(rainbowprivatekeyspec keyspec)
    {
        this(keyspec.getinva1(), keyspec.getb1(), keyspec.getinva2(), keyspec
            .getb2(), keyspec.getvi(), keyspec.getlayers());
    }

    public bcrainbowprivatekey(
        rainbowprivatekeyparameters params)
    {
        this(params.getinva1(), params.getb1(), params.getinva2(), params.getb2(), params.getvi(), params.getlayers());
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
     * getter for the translation part of the private quadratic map l1.
     *
     * @return b1 the translation part of l1
     */
    public short[] getb1()
    {
        return this.b1;
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
     * returns the array of vi-s
     *
     * @return the vi
     */
    public int[] getvi()
    {
        return vi;
    }

    /**
     * compare this rainbow private key with another object.
     *
     * @param other the other object
     * @return the result of the comparison
     */
    public boolean equals(object other)
    {
        if (other == null || !(other instanceof bcrainbowprivatekey))
        {
            return false;
        }
        bcrainbowprivatekey otherkey = (bcrainbowprivatekey)other;

        boolean eq = true;
        // compare using shortcut rule ( && instead of &)
        eq = eq && rainbowutil.equals(a1inv, otherkey.getinva1());
        eq = eq && rainbowutil.equals(a2inv, otherkey.getinva2());
        eq = eq && rainbowutil.equals(b1, otherkey.getb1());
        eq = eq && rainbowutil.equals(b2, otherkey.getb2());
        eq = eq && arrays.equals(vi, otherkey.getvi());
        if (layers.length != otherkey.getlayers().length)
        {
            return false;
        }
        for (int i = layers.length - 1; i >= 0; i--)
        {
            eq &= layers[i].equals(otherkey.getlayers()[i]);
        }
        return eq;
    }

    public int hashcode()
    {
        int hash = layers.length;

        hash = hash * 37 + org.ripple.bouncycastle.util.arrays.hashcode(a1inv);
        hash = hash * 37 + org.ripple.bouncycastle.util.arrays.hashcode(b1);
        hash = hash * 37 + org.ripple.bouncycastle.util.arrays.hashcode(a2inv);
        hash = hash * 37 + org.ripple.bouncycastle.util.arrays.hashcode(b2);
        hash = hash * 37 + org.ripple.bouncycastle.util.arrays.hashcode(vi);

        for (int i = layers.length - 1; i >= 0; i--)
        {
            hash = hash * 37 + layers[i].hashcode();
        }


        return hash;
    }

    /**
     * @return name of the algorithm - "rainbow"
     */
    public final string getalgorithm()
    {
        return "rainbow";
    }

    public byte[] getencoded()
    {
        rainbowprivatekey privatekey = new rainbowprivatekey(a1inv, b1, a2inv, b2, vi, layers);

        privatekeyinfo pki;
        try
        {
            algorithmidentifier algorithmidentifier = new algorithmidentifier(pqcobjectidentifiers.rainbow, dernull.instance);
            pki = new privatekeyinfo(algorithmidentifier, privatekey);
        }
        catch (ioexception e)
        {
            e.printstacktrace();
            return null;
        }
        try
        {
            byte[] encoded = pki.getencoded();
            return encoded;
        }
        catch (ioexception e)
        {
            e.printstacktrace();
            return null;
        }
    }

    public string getformat()
    {
        return "pkcs#8";
    }
}
