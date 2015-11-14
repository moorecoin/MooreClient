package org.ripple.bouncycastle.pqc.crypto.rainbow;

public class rainbowpublickeyparameters
    extends rainbowkeyparameters
{
    private short[][] coeffquadratic;
    private short[][] coeffsingular;
    private short[] coeffscalar;

    /**
     * constructor
     *
     * @param doclength
     * @param coeffquadratic
     * @param coeffsingular
     * @param coeffscalar
     */
    public rainbowpublickeyparameters(int doclength,
                                      short[][] coeffquadratic, short[][] coeffsingular,
                                      short[] coeffscalar)
    {
        super(false, doclength);

        this.coeffquadratic = coeffquadratic;
        this.coeffsingular = coeffsingular;
        this.coeffscalar = coeffscalar;

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
