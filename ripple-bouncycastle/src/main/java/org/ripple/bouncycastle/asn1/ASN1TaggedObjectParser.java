package org.ripple.bouncycastle.asn1;

import java.io.ioexception;

public interface asn1taggedobjectparser
    extends asn1encodable, inmemoryrepresentable
{
    public int gettagno();
    
    public asn1encodable getobjectparser(int tag, boolean isexplicit)
        throws ioexception;
}
