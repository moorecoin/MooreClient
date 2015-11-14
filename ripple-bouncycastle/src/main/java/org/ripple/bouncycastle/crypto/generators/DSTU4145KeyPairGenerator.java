package org.ripple.bouncycastle.crypto.generators;

import org.ripple.bouncycastle.crypto.asymmetriccipherkeypair;
import org.ripple.bouncycastle.crypto.params.ecprivatekeyparameters;
import org.ripple.bouncycastle.crypto.params.ecpublickeyparameters;

public class dstu4145keypairgenerator
    extends eckeypairgenerator
{
    public asymmetriccipherkeypair generatekeypair()
    {
        asymmetriccipherkeypair pair = super.generatekeypair();

        ecpublickeyparameters pub = (ecpublickeyparameters)pair.getpublic();
        ecprivatekeyparameters priv = (ecprivatekeyparameters)pair.getprivate();

        pub = new ecpublickeyparameters(pub.getq().negate(), pub.getparameters());

        return new asymmetriccipherkeypair(pub, priv);
    }
}
