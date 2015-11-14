package org.ripple.bouncycastle.jce.provider;

import java.util.collection;

import org.ripple.bouncycastle.util.collectionstore;
import org.ripple.bouncycastle.util.selector;
import org.ripple.bouncycastle.x509.x509collectionstoreparameters;
import org.ripple.bouncycastle.x509.x509storeparameters;
import org.ripple.bouncycastle.x509.x509storespi;

/**
 * this class is a collection based bouncy castle
 * {@link org.ripple.bouncycastle.x509.x509store} spi implementation for certificate
 * pairs.
 *
 * @see org.ripple.bouncycastle.x509.x509store
 * @see org.ripple.bouncycastle.x509.x509certificatepair
 */
public class x509storecertpaircollection extends x509storespi
{

    private collectionstore _store;

    public x509storecertpaircollection()
    {
    }

    /**
     * initializes this store.
     *
     * @param params the {@link x509collectionstoreparameters}s for this store.
     * @throws illegalargumentexception if <code>params</code> is no instance of
     *                                  <code>x509collectionstoreparameters</code>.
     */
    public void engineinit(x509storeparameters params)
    {
        if (!(params instanceof x509collectionstoreparameters))
        {
            throw new illegalargumentexception(
                "initialization parameters must be an instance of "
                    + x509collectionstoreparameters.class.getname()
                    + ".");
        }

        _store = new collectionstore(((x509collectionstoreparameters)params)
            .getcollection());
    }

    /**
     * returns a colelction of certificate pairs which match the given
     * <code>selector</code>.
     * <p/>
     * the returned collection contains
     * {@link org.ripple.bouncycastle.x509.x509certificatepair}s. the selector must be
     * a {@link org.ripple.bouncycastle.x509.x509certpairstoreselector} to select
     * certificate pairs.
     *
     * @return a collection with matching certificate pairs.
     */
    public collection enginegetmatches(selector selector)
    {
        return _store.getmatches(selector);
    }
}
