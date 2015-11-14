package org.ripple.bouncycastle.asn1;

import java.io.outputstream;

public abstract class asn1generator
{
    protected outputstream _out;
    
    public asn1generator(outputstream out)
    {
        _out = out;
    }
    
    public abstract outputstream getrawoutputstream();
}
