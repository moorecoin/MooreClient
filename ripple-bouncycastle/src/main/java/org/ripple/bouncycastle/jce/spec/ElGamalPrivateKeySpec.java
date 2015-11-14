package org.ripple.bouncycastle.jce.spec;

import java.math.biginteger;

/**
 * this class specifies an elgamal private key with its associated parameters.
 *
 * @see elgamalpublickeyspec
 */
public class elgamalprivatekeyspec
    extends elgamalkeyspec
{
    private biginteger  x;

    public elgamalprivatekeyspec(
        biginteger              x,
        elgamalparameterspec    spec)
    {
        super(spec);

        this.x = x;
    }

    /**
     * returns the private value <code>x</code>.
     *
     * @return the private value <code>x</code>
     */
    public biginteger getx()
    {
        return x;
    }
}
