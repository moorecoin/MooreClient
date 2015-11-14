package org.ripple.bouncycastle.pqc.jcajce.spec;


import java.security.spec.keyspec;

/**
 * this class provides a specification for a rainbowsignature public key.
 *
 * @see keyspec
 */
public class rainbowpublickeyspec
    implements keyspec
{
    private short[][] coeffquadratic;
    private short[][] coeffsingular;
    private short[] coeffscalar;
    private int doclength; // length of possible document to sign

    /**
     * constructor
     *
     * @param doclength
     * @param coeffquadratic
     * @param coeffsingular
     * @param coeffscalar
     */
    public rainbowpublickeyspec(int doclength,
                                short[][] coeffquadratic, short[][] coeffsingular,
                                short[] coeffscalar)
    {
        this.doclength = doclength;
        this.coeffquadratic = coeffquadratic;
        this.coeffsingular = coeffsingular;
        this.coeffscalar = coeffscalar;
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
        return coeffsingular;
    }

    /**
     * @return the coeffscalar
     */
    public short[] getcoeffscalar()
    {
        return coeffscalar;
    }
}
