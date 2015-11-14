package org.ripple.bouncycastle.crypto.engines;

/**
 * an implementation of the seed key wrapper based on rfc 4010/rfc 3394.
 * <p>
 * for further details see: <a href="http://www.ietf.org/rfc/rfc4010.txt">http://www.ietf.org/rfc/rfc4010.txt</a>.
 */
public class seedwrapengine
    extends rfc3394wrapengine
{
    public seedwrapengine()
    {
        super(new seedengine());
    }
}
