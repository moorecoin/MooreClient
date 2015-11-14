package org.ripple.bouncycastle.crypto.params;

public class eckeyparameters
    extends asymmetrickeyparameter
{
    ecdomainparameters params;

    protected eckeyparameters(
        boolean             isprivate,
        ecdomainparameters  params)
    {
        super(isprivate);

        this.params = params;
    }

    public ecdomainparameters getparameters()
    {
        return params;
    }
}
