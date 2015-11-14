package org.ripple.bouncycastle.crypto.params;

import org.ripple.bouncycastle.crypto.cipherparameters;

public class mqvpublicparameters
    implements cipherparameters
{
    private ecpublickeyparameters staticpublickey;
    private ecpublickeyparameters ephemeralpublickey;

    public mqvpublicparameters(
        ecpublickeyparameters   staticpublickey,
        ecpublickeyparameters   ephemeralpublickey)
    {
        this.staticpublickey = staticpublickey;
        this.ephemeralpublickey = ephemeralpublickey;
    }

    public ecpublickeyparameters getstaticpublickey()
    {
        return staticpublickey;
    }

    public ecpublickeyparameters getephemeralpublickey()
    {
        return ephemeralpublickey;
    }
}
