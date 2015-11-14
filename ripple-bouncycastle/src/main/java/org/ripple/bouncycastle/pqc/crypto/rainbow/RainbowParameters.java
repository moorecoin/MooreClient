package org.ripple.bouncycastle.pqc.crypto.rainbow;

import org.ripple.bouncycastle.crypto.cipherparameters;

public class rainbowparameters
    implements cipherparameters
{

    /**
     * default params
     */
    /*
      * vi = vinegars per layer whereas n is vu (vu = 33 = n) such that
      *
      * v1 = 6; o1 = 12-6 = 6
      *
      * v2 = 12; o2 = 17-12 = 5
      *
      * v3 = 17; o3 = 22-17 = 5
      *
      * v4 = 22; o4 = 33-22 = 11
      *
      * v5 = 33; (o5 = 0)
      */
    private final int[] default_vi = {6, 12, 17, 22, 33};

    private int[] vi;// set of vinegar vars per layer.

    /**
     * default constructor the elements of the array containing the number of
     * vinegar variables in each layer are set to the default values here.
     */
    public rainbowparameters()
    {
        this.vi = this.default_vi;
    }

    /**
     * constructor with parameters
     *
     * @param vi the elements of the array containing the number of vinegar
     *           variables per layer are set to the values of the input array.
     */
    public rainbowparameters(int[] vi)
    {
        this.vi = vi;
        try
        {
            checkparams();
        }
        catch (exception e)
        {
            e.printstacktrace();
        }
    }

    private void checkparams()
        throws exception
    {
        if (vi == null)
        {
            throw new exception("no layers defined.");
        }
        if (vi.length > 1)
        {
            for (int i = 0; i < vi.length - 1; i++)
            {
                if (vi[i] >= vi[i + 1])
                {
                    throw new exception(
                        "v[i] has to be smaller than v[i+1]");
                }
            }
        }
        else
        {
            throw new exception(
                "rainbow needs at least 1 layer, such that v1 < v2.");
        }
    }

    /**
     * getter for the number of layers
     *
     * @return the number of layers
     */
    public int getnumoflayers()
    {
        return this.vi.length - 1;
    }

    /**
     * getter for the number of all the polynomials in rainbow
     *
     * @return the number of the polynomials
     */
    public int getdoclength()
    {
        return vi[vi.length - 1] - vi[0];
    }

    /**
     * getter for the array containing the number of vinegar-variables per layer
     *
     * @return the numbers of vinegars per layer
     */
    public int[] getvi()
    {
        return this.vi;
    }
}
