package org.ripple.bouncycastle.crypto.params;

import java.math.biginteger;

public class elgamalprivatekeyparameters
    extends elgamalkeyparameters
{
    private biginteger      x;

    public elgamalprivatekeyparameters(
        biginteger      x,
        elgamalparameters    params)
    {
        super(true, params);

        this.x = x;
    }   

    public biginteger getx()
    {
        return x;
    }

    public boolean equals(
        object  obj)
    {
        if (!(obj instanceof elgamalprivatekeyparameters))
        {
            return false;
        }

        elgamalprivatekeyparameters  pkey = (elgamalprivatekeyparameters)obj;

        if (!pkey.getx().equals(x))
        {
            return false;
        }

        return super.equals(obj);
    }
    
    public int hashcode()
    {
        return getx().hashcode();
    }
}
