package org.ripple.bouncycastle.asn1;

import java.io.ioexception;

public interface asn1applicationspecificparser
    extends asn1encodable, inmemoryrepresentable
{
    asn1encodable readobject()
        throws ioexception;
}
