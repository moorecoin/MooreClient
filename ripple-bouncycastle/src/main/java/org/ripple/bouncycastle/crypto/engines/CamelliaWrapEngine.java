package org.ripple.bouncycastle.crypto.engines;

/**
 * an implementation of the camellia key wrapper based on rfc 3657/rfc 3394.
 * <p>
 * for further details see: <a href="http://www.ietf.org/rfc/rfc3657.txt">http://www.ietf.org/rfc/rfc3657.txt</a>.
 */
public class camelliawrapengine
    extends rfc3394wrapengine
{
    public camelliawrapengine()
    {
        super(new camelliaengine());
    }
}
