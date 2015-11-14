package org.ripple.bouncycastle.jce.spec;

import java.security.spec.keyspec;

public class elgamalkeyspec
    implements keyspec
{
    private elgamalparameterspec  spec;

    public elgamalkeyspec(
        elgamalparameterspec  spec)
    {
        this.spec = spec;
    }

    public elgamalparameterspec getparams()
    {
        return spec;
    }
}
