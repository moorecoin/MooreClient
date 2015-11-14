package org.ripple.bouncycastle.crypto.params;

import java.math.biginteger;

/**
 * public key parameters for naccachestern cipher. for details on this cipher,
 * please see
 * 
 * http://www.gemplus.com/smart/rd/publications/pdf/ns98pkcs.pdf
 */
public class naccachesternkeyparameters extends asymmetrickeyparameter
{

    private biginteger g, n;

    int lowersigmabound;

    /**
     * @param privatekey
     */
    public naccachesternkeyparameters(boolean privatekey, biginteger g, biginteger n, int lowersigmabound)
    {
        super(privatekey);
        this.g = g;
        this.n = n;
        this.lowersigmabound = lowersigmabound;
    }

    /**
     * @return returns the g.
     */
    public biginteger getg()
    {
        return g;
    }

    /**
     * @return returns the lowersigmabound.
     */
    public int getlowersigmabound()
    {
        return lowersigmabound;
    }

    /**
     * @return returns the n.
     */
    public biginteger getmodulus()
    {
        return n;
    }

}
