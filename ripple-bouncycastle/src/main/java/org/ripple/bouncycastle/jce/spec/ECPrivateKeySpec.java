package org.ripple.bouncycastle.jce.spec;

import java.math.biginteger;

/**
 * elliptic curve private key specification.
 */
public class ecprivatekeyspec
    extends eckeyspec
{
    private biginteger    d;

    /**
     * base constructor
     *
     * @param d the private number for the key.
     * @param spec the domain parameters for the curve being used.
     */
    public ecprivatekeyspec(
        biginteger      d,
        ecparameterspec spec)
    {
        super(spec);

        this.d = d;
    }

    /**
     * return the private number d
     */
    public biginteger getd()
    {
        return d;
    }
}
