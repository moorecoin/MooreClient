package org.ripple.bouncycastle.crypto.params;

import org.ripple.bouncycastle.math.ec.ecpoint;

public class ecpublickeyparameters
    extends eckeyparameters
{
    ecpoint q;

    public ecpublickeyparameters(
        ecpoint             q,
        ecdomainparameters  params)
    {
        super(false, params);
        this.q = q;
    }

    public ecpoint getq()
    {
        return q;
    }
}
