package org.ripple.bouncycastle.jce.spec;

import java.math.biginteger;

/**
 * this class specifies an elgamal public key with its associated parameters.
 *
 * @see elgamalprivatekeyspec
 */
public class elgamalpublickeyspec
    extends elgamalkeyspec
{
    private biginteger  y;

    public elgamalpublickeyspec(
        biginteger              y,
        elgamalparameterspec    spec)
    {
        super(spec);

        this.y = y;
    }

    /**
     * returns the public value <code>y</code>.
     *
     * @return the public value <code>y</code>
     */
    public biginteger gety()
    {
        return y;
    }
}
