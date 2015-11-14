package org.ripple.bouncycastle.pqc.crypto.gmss;

import org.ripple.bouncycastle.util.arrays;

/**
 * this class provides a specification for the gmss parameters that are used by
 * the gmsskeypairgenerator and gmsssignature classes.
 *
 * @see org.ripple.bouncycastle.pqc.crypto.gmss.gmsskeypairgenerator
 */
public class gmssparameters
{
    /**
     * the number of authentication tree layers.
     */
    private int numoflayers;

    /**
     * the height of the authentication trees of each layer.
     */
    private int[] heightoftrees;

    /**
     * the winternitz parameter 'w' of each layer.
     */
    private int[] winternitzparameter;

    /**
     * the parameter k needed for the authentication path computation
     */
    private int[] k;

    /**
     * the constructor for the parameters of the gmsskeypairgenerator.
     * <p/>
     *
     * @param layers              the number of authentication tree layers
     * @param heightoftrees       the height of the authentication trees
     * @param winternitzparameter the winternitz parameter 'w' of each layer
     * @param k                   parameter for authpath computation
     */
    public gmssparameters(int layers, int[] heightoftrees, int[] winternitzparameter, int[] k)
        throws illegalargumentexception
    {
        init(layers, heightoftrees, winternitzparameter, k);
    }

    private void init(int layers, int[] heightoftrees,
                      int[] winternitzparameter, int[] k)
        throws illegalargumentexception
    {
        boolean valid = true;
        string errmsg = "";
        this.numoflayers = layers;
        if ((numoflayers != winternitzparameter.length)
            || (numoflayers != heightoftrees.length)
            || (numoflayers != k.length))
        {
            valid = false;
            errmsg = "unexpected parameterset format";
        }
        for (int i = 0; i < numoflayers; i++)
        {
            if ((k[i] < 2) || ((heightoftrees[i] - k[i]) % 2 != 0))
            {
                valid = false;
                errmsg = "wrong parameter k (k >= 2 and h-k even required)!";
            }

            if ((heightoftrees[i] < 4) || (winternitzparameter[i] < 2))
            {
                valid = false;
                errmsg = "wrong parameter h or w (h > 3 and w > 1 required)!";
            }
        }

        if (valid)
        {
            this.heightoftrees = arrays.clone(heightoftrees);
            this.winternitzparameter = arrays.clone(winternitzparameter);
            this.k = arrays.clone(k);
        }
        else
        {
            throw new illegalargumentexception(errmsg);
        }
    }

    public gmssparameters(int keysize)
        throws illegalargumentexception
    {
        if (keysize <= 10)
        { // create 2^10 keys
            int[] defh = {10};
            int[] defw = {3};
            int[] defk = {2};
            this.init(defh.length, defh, defw, defk);
        }
        else if (keysize <= 20)
        { // create 2^20 keys
            int[] defh = {10, 10};
            int[] defw = {5, 4};
            int[] defk = {2, 2};
            this.init(defh.length, defh, defw, defk);
        }
        else
        { // create 2^40 keys, keygen lasts around 80 seconds
            int[] defh = {10, 10, 10, 10};
            int[] defw = {9, 9, 9, 3};
            int[] defk = {2, 2, 2, 2};
            this.init(defh.length, defh, defw, defk);
        }
    }

    /**
     * returns the number of levels of the authentication trees.
     *
     * @return the number of levels of the authentication trees.
     */
    public int getnumoflayers()
    {
        return numoflayers;
    }

    /**
     * returns the array of height (for each layer) of the authentication trees
     *
     * @return the array of height (for each layer) of the authentication trees
     */
    public int[] getheightoftrees()
    {
        return arrays.clone(heightoftrees);
    }

    /**
     * returns the array of winternitzparameter (for each layer) of the
     * authentication trees
     *
     * @return the array of winternitzparameter (for each layer) of the
     *         authentication trees
     */
    public int[] getwinternitzparameter()
    {
        return arrays.clone(winternitzparameter);
    }

    /**
     * returns the parameter k needed for authentication path computation
     *
     * @return the parameter k needed for authentication path computation
     */
    public int[] getk()
    {
        return arrays.clone(k);
    }
}
