package org.ripple.bouncycastle.pqc.crypto.ntru;

import org.ripple.bouncycastle.crypto.params.asymmetrickeyparameter;

public class ntruencryptionkeyparameters
    extends asymmetrickeyparameter
{
    final protected ntruencryptionparameters params;

    public ntruencryptionkeyparameters(boolean privatekey, ntruencryptionparameters params)
    {
        super(privatekey);
        this.params = params;
    }

    public ntruencryptionparameters getparameters()
    {
        return params;
    }
}
