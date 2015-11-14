package org.ripple.bouncycastle.x509;

import org.ripple.bouncycastle.x509.util.streamparser;
import org.ripple.bouncycastle.x509.util.streamparsingexception;

import java.io.bytearrayinputstream;
import java.io.inputstream;
import java.security.nosuchalgorithmexception;
import java.security.nosuchproviderexception;
import java.security.provider;
import java.util.collection;

/**
 *
 * this class allows access to different implementations for reading x.509
 * objects from streams.
 * <p>
 * a x509streamparser is used to read a collection of objects or a single object
 * of a certain x.509 object structure. e.g. one x509streamparser can read
 * certificates, another one crls, certification paths, attribute certificates
 * and so on. the kind of object structure is specified with the
 * <code>algorithm</code> parameter to the <code>getinstance</code> methods.
 * <p>
 * implementations must implement the
 * {@link org.ripple.bouncycastle.x509.x509streamparserspi}.
 */
public class x509streamparser
    implements streamparser
{
    /**
     * generates a streamparser object that implements the specified type. if
     * the default provider package provides an implementation of the requested
     * type, an instance of streamparser containing that implementation is
     * returned. if the type is not available in the default package, other
     * packages are searched.
     *
     * @param type
     *            the name of the requested x.509 object type.
     * @return a streamparser object for the specified type.
     *
     * @exception nosuchparserexception
     *                if the requested type is not available in the default
     *                provider package or any of the other provider packages
     *                that were searched.
     */
    public static x509streamparser getinstance(string type)
        throws nosuchparserexception
    {
        try
        {
            x509util.implementation impl = x509util.getimplementation("x509streamparser", type);

            return createparser(impl);
        }
        catch (nosuchalgorithmexception e)
        {
            throw new nosuchparserexception(e.getmessage());
        }
    }

    /**
     * generates a x509streamparser object for the specified type from the
     * specified provider.
     *
     * @param type
     *            the name of the requested x.509 object type.
     * @param provider
     *            the name of the provider.
     *
     * @return a x509streamparser object for the specified type.
     *
     * @exception nosuchparserexception
     *                if the type is not available from the specified provider.
     *
     * @exception nosuchproviderexception
     *                if the provider can not be found.
     *
     * @see provider
     */
    public static x509streamparser getinstance(string type, string provider)
        throws nosuchparserexception, nosuchproviderexception
    {
        return getinstance(type, x509util.getprovider(provider));
    }

    /**
     * generates a x509streamparser object for the specified type from the
     * specified provider.
     *
     * @param type
     *            the name of the requested x.509 object type.
     * @param provider
     *            the provider to use.
     *
     * @return a x509streamparser object for the specified type.
     *
     * @exception nosuchparserexception
     *                if the type is not available from the specified provider.
     *
     * @see provider
     */
    public static x509streamparser getinstance(string type, provider provider)
        throws nosuchparserexception
    {
        try
        {
            x509util.implementation impl = x509util.getimplementation("x509streamparser", type, provider);

            return createparser(impl);
        }
        catch (nosuchalgorithmexception e)
        {
            throw new nosuchparserexception(e.getmessage());
        }
    }

    private static x509streamparser createparser(x509util.implementation impl)
    {
        x509streamparserspi spi = (x509streamparserspi)impl.getengine();

        return new x509streamparser(impl.getprovider(), spi);
    }

    private provider            _provider;
    private x509streamparserspi _spi;

    private x509streamparser(
        provider provider,
        x509streamparserspi spi)
    {
        _provider = provider;
        _spi = spi;
    }

    public provider getprovider()
    {
        return _provider;
    }

    public void init(inputstream stream)
    {
        _spi.engineinit(stream);
    }

    public void init(byte[] data)
    {
        _spi.engineinit(new bytearrayinputstream(data));
    }

    public object read()
        throws streamparsingexception
    {
        return _spi.engineread();
    }

    public collection readall()
        throws streamparsingexception
    {
        return _spi.enginereadall();
    }
}
