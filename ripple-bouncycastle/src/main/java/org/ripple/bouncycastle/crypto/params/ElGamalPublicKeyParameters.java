package org.ripple.bouncycastle.crypto.params;

import java.math.biginteger;

public class elgamalpublickeyparameters
    extends elgamalkeyparameters
{
    private biginteger      y;

    public elgamalpublickeyparameters(
        biginteger      y,
        elgamalparameters    params)
    {
        super(false, params);

        this.y = y;
    }   

    public biginteger gety()
    {
        return y;
    }

    public int hashcode()
    {
        return y.hashcode() ^ super.hashcode();
    }

    public boolean equals(
        object  obj)
    {
        if (!(obj instanceof elgamalpublickeyparameters))
        {
            return false;
        }

        elgamalpublickeyparameters   other = (elgamalpublickeyparameters)obj;

        return other.gety().equals(y) && super.equals(obj);
    }
}
