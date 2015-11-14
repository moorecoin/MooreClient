package org.ripple.bouncycastle.x509;

import org.ripple.bouncycastle.util.selector;

import java.util.collection;

public abstract class x509storespi
{
    public abstract void engineinit(x509storeparameters parameters);

    public abstract collection enginegetmatches(selector selector);
}
