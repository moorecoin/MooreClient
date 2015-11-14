package org.ripple.bouncycastle.crypto.params;

import org.ripple.bouncycastle.crypto.cipherparameters;

import java.math.biginteger;

public class rsablindingparameters
    implements cipherparameters
{
    private rsakeyparameters publickey;
    private biginteger       blindingfactor;

    public rsablindingparameters(
        rsakeyparameters publickey,
        biginteger       blindingfactor)
    {
        if (publickey instanceof rsaprivatecrtkeyparameters)
        {
            throw new illegalargumentexception("rsa parameters should be for a public key");
        }
        
        this.publickey = publickey;
        this.blindingfactor = blindingfactor;
    }

    public rsakeyparameters getpublickey()
    {
        return publickey;
    }

    public biginteger getblindingfactor()
    {
        return blindingfactor;
    }
}
