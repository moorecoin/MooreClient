package org.ripple.bouncycastle.jce.provider;

import java.util.collection;

import org.ripple.bouncycastle.util.collectionstore;
import org.ripple.bouncycastle.util.selector;
import org.ripple.bouncycastle.x509.x509collectionstoreparameters;
import org.ripple.bouncycastle.x509.x509storeparameters;
import org.ripple.bouncycastle.x509.x509storespi;

public class x509storeattrcertcollection
    extends x509storespi
{
    private collectionstore _store;

    public x509storeattrcertcollection()
    {
    }

    public void engineinit(x509storeparameters params)
    {
        if (!(params instanceof x509collectionstoreparameters))
        {
            throw new illegalargumentexception(params.tostring());
        }

        _store = new collectionstore(((x509collectionstoreparameters)params).getcollection());
    }

    public collection enginegetmatches(selector selector)
    {
        return _store.getmatches(selector);
    }
}
