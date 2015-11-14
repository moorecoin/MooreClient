package org.ripple.bouncycastle.jcajce.provider.symmetric.util;

import java.security.algorithmparametersspi;
import java.security.spec.algorithmparameterspec;
import java.security.spec.invalidparameterspecexception;

public abstract class basealgorithmparameters
    extends algorithmparametersspi
{
    protected boolean isasn1formatstring(string format)
    {
        return format == null || format.equals("asn.1");
    }

    protected algorithmparameterspec enginegetparameterspec(
        class paramspec)
        throws invalidparameterspecexception
    {
        if (paramspec == null)
        {
            throw new nullpointerexception("argument to getparameterspec must not be null");
        }

        return localenginegetparameterspec(paramspec);
    }

    protected abstract algorithmparameterspec localenginegetparameterspec(class paramspec)
        throws invalidparameterspecexception;
}
