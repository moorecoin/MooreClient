package org.ripple.bouncycastle.crypto.params;

public class dsakeyparameters
    extends asymmetrickeyparameter
{
    private dsaparameters    params;

    public dsakeyparameters(
        boolean         isprivate,
        dsaparameters   params)
    {
        super(isprivate);

        this.params = params;
    }   

    public dsaparameters getparameters()
    {
        return params;
    }
}
