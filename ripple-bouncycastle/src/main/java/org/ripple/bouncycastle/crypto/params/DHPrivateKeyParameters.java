package org.ripple.bouncycastle.crypto.params;

import java.math.biginteger;

public class dhprivatekeyparameters
    extends dhkeyparameters
{
    private biginteger      x;

    public dhprivatekeyparameters(
        biginteger      x,
        dhparameters    params)
    {
        super(true, params);

        this.x = x;
    }   

    public biginteger getx()
    {
        return x;
    }

    public int hashcode()
    {
        return x.hashcode() ^ super.hashcode();
    }
    
    public boolean equals(
        object  obj)
    {
        if (!(obj instanceof dhprivatekeyparameters))
        {
            return false;
        }

        dhprivatekeyparameters  other = (dhprivatekeyparameters)obj;

        return other.getx().equals(this.x) && super.equals(obj);
    }
}
