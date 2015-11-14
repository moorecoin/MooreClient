package org.ripple.bouncycastle.jce.spec;

import java.security.spec.keyspec;

/**
 * base class for an elliptic curve key spec
 */
public class eckeyspec
    implements keyspec
{
    private ecparameterspec     spec;

    protected eckeyspec(
        ecparameterspec spec)
    {
        this.spec = spec;
    }

    /**
     * return the domain parameters for the curve
     */
    public ecparameterspec getparams()
    {
        return spec;
    }
}
