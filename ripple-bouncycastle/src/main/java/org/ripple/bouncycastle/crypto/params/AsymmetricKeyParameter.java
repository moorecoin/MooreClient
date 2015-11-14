package org.ripple.bouncycastle.crypto.params;

import org.ripple.bouncycastle.crypto.cipherparameters;

public class asymmetrickeyparameter
    implements cipherparameters
{
    boolean privatekey;

    public asymmetrickeyparameter(
        boolean privatekey)
    {
        this.privatekey = privatekey;
    }

    public boolean isprivate()
    {
        return privatekey;
    }
}
