package org.ripple.bouncycastle.pqc.jcajce.provider.rainbow;

import java.security.publickey;

import org.ripple.bouncycastle.asn1.dernull;
import org.ripple.bouncycastle.asn1.x509.algorithmidentifier;
import org.ripple.bouncycastle.pqc.asn1.pqcobjectidentifiers;
import org.ripple.bouncycastle.pqc.asn1.rainbowpublickey;
import org.ripple.bouncycastle.pqc.crypto.rainbow.rainbowparameters;
import org.ripple.bouncycastle.pqc.crypto.rainbow.rainbowpublickeyparameters;
import org.ripple.bouncycastle.pqc.crypto.rainbow.util.rainbowutil;
import org.ripple.bouncycastle.pqc.jcajce.provider.util.keyutil;
import org.ripple.bouncycastle.pqc.jcajce.spec.rainbowpublickeyspec;
import org.ripple.bouncycastle.util.arrays;

/**
 * this class implements cipherparameters and publickey.
 * <p/>
 * the public key in rainbow consists of n - v1 polynomial components of the
 * private key's f and the field structure of the finite field k.
 * <p/>
 * the quadratic (or mixed) coefficients of the polynomials from the public key
 * are stored in the 2-dimensional array in lexicographical order, requiring n *
 * (n + 1) / 2 entries for each polynomial. the singular terms are stored in a
 * 2-dimensional array requiring n entries per polynomial, the scalar term of
 * each polynomial is stored in a 1-dimensional array.
 * <p/>
 * more detailed information on the public key is to be found in the paper of
 * jintai ding, dieter schmidt: rainbow, a new multivariable polynomial
 * signature scheme. acns 2005: 164-175 (http://dx.doi.org/10.1007/11496137_12)
 */
public class bcrainbowpublickey
    implements publickey
{
    private static final long serialversionuid = 1l;

    private short[][] coeffquadratic;
    private short[][] coeffsingular;
    private short[] coeffscalar;
    private int doclength; // length of possible document to sign

    private rainbowparameters rainbowparams;

    /**
     * constructor
     *
     * @param doclength
     * @param coeffquadratic
     * @param coeffsingular
     * @param coeffscalar
     */
    public bcrainbowpublickey(int doclength,
                              short[][] coeffquadratic, short[][] coeffsingular,
                              short[] coeffscalar)
    {
        this.doclength = doclength;
        this.coeffquadratic = coeffquadratic;
        this.coeffsingular = coeffsingular;
        this.coeffscalar = coeffscalar;
    }

    /**
     * constructor (used by the {@link rainbowkeyfactoryspi}).
     *
     * @param keyspec a {@link rainbowpublickeyspec}
     */
    public bcrainbowpublickey(rainbowpublickeyspec keyspec)
    {
        this(keyspec.getdoclength(), keyspec.getcoeffquadratic(), keyspec
            .getcoeffsingular(), keyspec.getcoeffscalar());
    }

    public bcrainbowpublickey(
        rainbowpublickeyparameters params)
    {
        this(params.getdoclength(), params.getcoeffquadratic(), params.getcoeffsingular(), params.getcoeffscalar());
    }

    /**
     * @return the doclength
     */
    public int getdoclength()
    {
        return this.doclength;
    }

    /**
     * @return the coeffquadratic
     */
    public short[][] getcoeffquadratic()
    {
        return coeffquadratic;
    }

    /**
     * @return the coeffsingular
     */
    public short[][] getcoeffsingular()
    {
        short[][] copy = new short[coeffsingular.length][];

        for (int i = 0; i != coeffsingular.length; i++)
        {
            copy[i] = arrays.clone(coeffsingular[i]);
        }

        return copy;
    }


    /**
     * @return the coeffscalar
     */
    public short[] getcoeffscalar()
    {
        return arrays.clone(coeffscalar);
    }

    /**
     * compare this rainbow public key with another object.
     *
     * @param other the other object
     * @return the result of the comparison
     */
    public boolean equals(object other)
    {
        if (other == null || !(other instanceof bcrainbowpublickey))
        {
            return false;
        }
        bcrainbowpublickey otherkey = (bcrainbowpublickey)other;

        return doclength == otherkey.getdoclength()
            && rainbowutil.equals(coeffquadratic, otherkey.getcoeffquadratic())
            && rainbowutil.equals(coeffsingular, otherkey.getcoeffsingular())
            && rainbowutil.equals(coeffscalar, otherkey.getcoeffscalar());
    }

    public int hashcode()
    {
        int hash = doclength;

        hash = hash * 37 + arrays.hashcode(coeffquadratic);
        hash = hash * 37 + arrays.hashcode(coeffsingular);
        hash = hash * 37 + arrays.hashcode(coeffscalar);

        return hash;
    }

    /**
     * @return name of the algorithm - "rainbow"
     */
    public final string getalgorithm()
    {
        return "rainbow";
    }

    public string getformat()
    {
        return "x.509";
    }

    public byte[] getencoded()
    {
        rainbowpublickey key = new rainbowpublickey(doclength, coeffquadratic, coeffsingular, coeffscalar);
        algorithmidentifier algorithmidentifier = new algorithmidentifier(pqcobjectidentifiers.rainbow, dernull.instance);

        return keyutil.getencodedsubjectpublickeyinfo(algorithmidentifier, key);
    }
}
