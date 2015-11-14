package org.ripple.bouncycastle.crypto.tls;

import org.ripple.bouncycastle.crypto.dsa;
import org.ripple.bouncycastle.crypto.params.asymmetrickeyparameter;
import org.ripple.bouncycastle.crypto.params.ecpublickeyparameters;
import org.ripple.bouncycastle.crypto.signers.ecdsasigner;

public class tlsecdsasigner
    extends tlsdsasigner
{

    public boolean isvalidpublickey(asymmetrickeyparameter publickey)
    {
        return publickey instanceof ecpublickeyparameters;
    }

    protected dsa createdsaimpl()
    {
        return new ecdsasigner();
    }
}
