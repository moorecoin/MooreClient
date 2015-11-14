package org.ripple.bouncycastle.x509;

import org.ripple.bouncycastle.util.selector;
import org.ripple.bouncycastle.util.store;

import java.security.nosuchalgorithmexception;
import java.security.nosuchproviderexception;
import java.security.provider;
import java.util.collection;

public class x509store
    implements store
{
    public static x509store getinstance(string type, x509storeparameters parameters)
        throws nosuchstoreexception
    {
        try
        {
            x509util.implementation impl = x509util.getimplementation("x509store", type);

            return createstore(impl, parameters);
        }
        catch (nosuchalgorithmexception e)
        {
            throw new nosuchstoreexception(e.getmessage());
        }
    }

    public static x509store getinstance(string type, x509storeparameters parameters, string provider)
        throws nosuchstoreexception, nosuchproviderexception
    {
        return getinstance(type, parameters, x509util.getprovider(provider));
    }

    public static x509store getinstance(string type, x509storeparameters parameters, provider provider)
        throws nosuchstoreexception
    {
        try
        {
            x509util.implementation impl = x509util.getimplementation("x509store", type, provider);

            return createstore(impl, parameters);
        }
        catch (nosuchalgorithmexception e)
        {
            throw new nosuchstoreexception(e.getmessage());
        }
    }

    private static x509store createstore(x509util.implementation impl, x509storeparameters parameters)
    {
        x509storespi spi = (x509storespi)impl.getengine();

        spi.engineinit(parameters);

        return new x509store(impl.getprovider(), spi);
    }

    private provider     _provider;
    private x509storespi _spi;

    private x509store(
        provider provider,
        x509storespi spi)
    {
        _provider = provider;
        _spi = spi;
    }

    public provider getprovider()
    {
       return _provider;
    }

    public collection getmatches(selector selector)
    {
        return _spi.enginegetmatches(selector);
    }
}
