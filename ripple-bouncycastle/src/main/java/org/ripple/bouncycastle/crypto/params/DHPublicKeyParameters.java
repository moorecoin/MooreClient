package org.ripple.bouncycastle.crypto.params;

import java.math.biginteger;

public class dhpublickeyparameters
    extends dhkeyparameters
{
    private biginteger      y;

    public dhpublickeyparameters(
        biginteger      y,
        dhparameters    params)
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
        if (!(obj instanceof dhpublickeyparameters))
        {
            return false;
        }

        dhpublickeyparameters   other = (dhpublickeyparameters)obj;

        return other.gety().equals(y) && super.equals(obj);
    }
}
