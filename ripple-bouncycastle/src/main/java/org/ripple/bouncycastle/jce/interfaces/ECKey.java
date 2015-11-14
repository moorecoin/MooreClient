package org.ripple.bouncycastle.jce.interfaces;

import org.ripple.bouncycastle.jce.spec.ecparameterspec;

/**
 * generic interface for an elliptic curve key.
 */
public interface eckey
{
    /**
     * return a parameter specification representing the ec domain parameters
     * for the key.
     */
    public ecparameterspec getparameters();
}
