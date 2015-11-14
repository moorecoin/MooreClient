package org.ripple.bouncycastle.asn1;

import java.io.bytearrayoutputstream;
import java.io.ioexception;
import java.io.outputstream;

public class dersequencegenerator
    extends dergenerator
{
    private final bytearrayoutputstream _bout = new bytearrayoutputstream();

    public dersequencegenerator(
        outputstream out)
        throws ioexception
    {
        super(out);
    }

    public dersequencegenerator(
        outputstream out,
        int          tagno,
        boolean      isexplicit)
        throws ioexception
    {
        super(out, tagno, isexplicit);
    }

    public void addobject(
        asn1encodable object)
        throws ioexception
    {
        object.toasn1primitive().encode(new deroutputstream(_bout));
    }
    
    public outputstream getrawoutputstream()
    {
        return _bout;
    }
    
    public void close() 
        throws ioexception
    {
        writederencoded(bertags.constructed | bertags.sequence, _bout.tobytearray());
    }
}
