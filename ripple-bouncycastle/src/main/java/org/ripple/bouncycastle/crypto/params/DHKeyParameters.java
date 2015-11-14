package org.ripple.bouncycastle.crypto.params;


public class dhkeyparameters
    extends asymmetrickeyparameter
{
    private dhparameters    params;

    protected dhkeyparameters(
        boolean         isprivate,
        dhparameters    params)
    {
        super(isprivate);

        this.params = params;
    }   

    public dhparameters getparameters()
    {
        return params;
    }

    public boolean equals(
        object  obj)
    {
        if (!(obj instanceof dhkeyparameters))
        {
            return false;
        }

        dhkeyparameters    dhkey = (dhkeyparameters)obj;

        if (params == null)
        {
            return dhkey.getparameters() == null;
        }
        else
        { 
            return params.equals(dhkey.getparameters());
        }
    }
    
    public int hashcode()
    {
        int code = isprivate() ? 0 : 1;
        
        if (params != null)
        {
            code ^= params.hashcode();
        }
        
        return code;
    }
}
