package org.ripple.bouncycastle.pqc.crypto.rainbow;

import org.ripple.bouncycastle.crypto.params.asymmetrickeyparameter;

public class rainbowkeyparameters 
    extends asymmetrickeyparameter
{
    private int doclength;

    public rainbowkeyparameters(
            boolean         isprivate,
            int             doclength)
    {
        super(isprivate);
        this.doclength = doclength;
    }

    /**
     * @return the doclength
     */
    public int getdoclength()
    {
        return this.doclength;
    }
}
