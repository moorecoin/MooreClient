package org.ripple.bouncycastle.crypto.params;


public class elgamalkeyparameters
    extends asymmetrickeyparameter
{
    private elgamalparameters    params;

    protected elgamalkeyparameters(
        boolean         isprivate,
        elgamalparameters    params)
    {
        super(isprivate);

        this.params = params;
    }   

    public elgamalparameters getparameters()
    {
        return params;
    }

    public int hashcode()
    {
        return (params != null) ? params.hashcode() : 0;
    }

    public boolean equals(
        object  obj)
    {
        if (!(obj instanceof elgamalkeyparameters))
        {
            return false;
        }

        elgamalkeyparameters    dhkey = (elgamalkeyparameters)obj;

        if (params == null)
        {
            return dhkey.getparameters() == null;
        }
        else
        { 
            return params.equals(dhkey.getparameters());
        }
    }
}
