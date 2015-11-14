package org.ripple.bouncycastle.crypto.params;

import org.ripple.bouncycastle.crypto.cipherparameters;

public class mqvprivateparameters
    implements cipherparameters
{
    private ecprivatekeyparameters staticprivatekey;
    private ecprivatekeyparameters ephemeralprivatekey;
    private ecpublickeyparameters ephemeralpublickey;

    public mqvprivateparameters(
        ecprivatekeyparameters  staticprivatekey,
        ecprivatekeyparameters  ephemeralprivatekey)
    {
        this(staticprivatekey, ephemeralprivatekey, null);
    }

    public mqvprivateparameters(
        ecprivatekeyparameters  staticprivatekey,
        ecprivatekeyparameters  ephemeralprivatekey,
        ecpublickeyparameters   ephemeralpublickey)
    {
        this.staticprivatekey = staticprivatekey;
        this.ephemeralprivatekey = ephemeralprivatekey;
        this.ephemeralpublickey = ephemeralpublickey;
    }

    public ecprivatekeyparameters getstaticprivatekey()
    {
        return staticprivatekey;
    }

    public ecprivatekeyparameters getephemeralprivatekey()
    {
        return ephemeralprivatekey;
    }

    public ecpublickeyparameters getephemeralpublickey()
    {
        return ephemeralpublickey;
    }
}
