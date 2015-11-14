package org.ripple.bouncycastle.crypto.params;

public class gost3410keyparameters
        extends asymmetrickeyparameter
{
    private gost3410parameters    params;

    public gost3410keyparameters(
        boolean         isprivate,
        gost3410parameters   params)
    {
        super(isprivate);

        this.params = params;
    }

    public gost3410parameters getparameters()
    {
        return params;
    }
}
