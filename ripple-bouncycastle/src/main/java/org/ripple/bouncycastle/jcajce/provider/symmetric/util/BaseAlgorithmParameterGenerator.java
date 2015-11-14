package org.ripple.bouncycastle.jcajce.provider.symmetric.util;

import java.security.algorithmparametergeneratorspi;
import java.security.securerandom;

public abstract class basealgorithmparametergenerator
    extends algorithmparametergeneratorspi
{
    protected securerandom  random;
    protected int           strength = 1024;

    protected void engineinit(
        int             strength,
        securerandom    random)
    {
        this.strength = strength;
        this.random = random;
    }
}
