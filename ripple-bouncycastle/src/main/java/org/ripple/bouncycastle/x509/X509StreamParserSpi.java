package org.ripple.bouncycastle.x509;

import org.ripple.bouncycastle.x509.util.streamparsingexception;

import java.io.inputstream;
import java.util.collection;

/**
 * this abstract class defines the service provider interface (spi) for
 * x509streamparser.
 *
 * @see org.ripple.bouncycastle.x509.x509streamparser
 *
 */
public abstract class x509streamparserspi
{
    /**
     * initializes this stream parser with the input stream.
     *
     * @param in the input stream.
     */
    public abstract void engineinit(inputstream in);

    /**
     * returns the next x.509 object of the type of this spi from the given
     * input stream.
     *
     * @return the next x.509 object in the stream or <code>null</code> if the
     *         end of the stream is reached.
     * @exception streamparsingexception
     *                if the object cannot be created from input stream.
     */
    public abstract object engineread() throws streamparsingexception;

    /**
     * returns all x.509 objects of the type of this spi from
     * the given input stream.
     *
     * @return a collection of all x.509 objects in the input stream or
     *         <code>null</code> if the end of the stream is reached.
     * @exception streamparsingexception
     *                if an object cannot be created from input stream.
     */
    public abstract collection enginereadall() throws streamparsingexception;
}
