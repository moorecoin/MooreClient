package org.ripple.bouncycastle.jcajce.provider.asymmetric.util;

import java.io.ioexception;
import java.math.biginteger;

public interface dsaencoder
{
    byte[] encode(biginteger r, biginteger s)
        throws ioexception;

    biginteger[] decode(byte[] sig)
        throws ioexception;
}
