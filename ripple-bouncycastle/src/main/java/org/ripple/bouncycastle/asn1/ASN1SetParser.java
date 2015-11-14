package org.ripple.bouncycastle.asn1;

import java.io.ioexception;

public interface asn1setparser
    extends asn1encodable, inmemoryrepresentable
{
    public asn1encodable readobject()
        throws ioexception;
}
