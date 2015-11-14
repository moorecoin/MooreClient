package org.ripple.bouncycastle.crypto.tls;

import org.ripple.bouncycastle.crypto.dsa;
import org.ripple.bouncycastle.crypto.params.asymmetrickeyparameter;
import org.ripple.bouncycastle.crypto.params.dsapublickeyparameters;
import org.ripple.bouncycastle.crypto.signers.dsasigner;

public class tlsdsssigner
    extends tlsdsasigner
{

    public boolean isvalidpublickey(asymmetrickeyparameter publickey)
    {
        return publickey instanceof dsapublickeyparameters;
    }

    protected dsa createdsaimpl()
    {
        return new dsasigner();
    }
}
