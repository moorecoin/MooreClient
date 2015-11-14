package org.ripple.bouncycastle.pqc.jcajce.spec;

import java.security.spec.algorithmparameterspec;

import org.ripple.bouncycastle.util.arrays;

/**
 * this class provides methods for setting and getting the rainbow-parameters
 * like number of vinegar-variables in the layers, number of layers and so on.
 * <p/>
 * more detailed information about the needed parameters for the rainbow
 * signature scheme is to be found in the paper of jintai ding, dieter schmidt:
 * rainbow, a new multivariable polynomial signature scheme. acns 2005: 164-175
 * (http://dx.doi.org/10.1007/11496137_12)
 */
public class rainbowparameterspec
    implements algorithmparameterspec
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
    private static final int[] default_vi = {6, 12, 17, 22, 33};

    private int[] vi;// set of vinegar vars per layer.

    /**
     * default constructor the elements of the array containing the number of
     * vinegar variables in each layer are set to the default values here.
     */
    public rainbowparameterspec()
    {
        this.vi = default_vi;
    }

    /**
     * constructor with parameters
     *
     * @param vi the elements of the array containing the number of vinegar
     *           variables per layer are set to the values of the input array.
     * @throws illegalargumentexception if the variables are invalid.
     */
    public rainbowparameterspec(int[] vi)
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
            throw new illegalargumentexception("no layers defined.");
        }
        if (vi.length > 1)
        {
            for (int i = 0; i < vi.length - 1; i++)
            {
                if (vi[i] >= vi[i + 1])
                {
                    throw new illegalargumentexception(
                        "v[i] has to be smaller than v[i+1]");
                }
            }
        }
        else
        {
            throw new illegalargumentexception(
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
    public int getdocumentlength()
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
        return arrays.clone(this.vi);
    }
}
