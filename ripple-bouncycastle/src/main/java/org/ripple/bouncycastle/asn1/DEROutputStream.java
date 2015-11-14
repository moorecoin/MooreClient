package org.ripple.bouncycastle.asn1;

import java.io.ioexception;
import java.io.outputstream;

/**
 * stream that outputs encoding based on distinguished encoding rules.
 */
public class deroutputstream
    extends asn1outputstream
{
    public deroutputstream(
        outputstream    os)
    {
        super(os);
    }

    public void writeobject(
        asn1encodable obj)
        throws ioexception
    {
        if (obj != null)
        {
            obj.toasn1primitive().toderobject().encode(this);
        }
        else
        {
            throw new ioexception("null object detected");
        }
    }

    asn1outputstream getdersubstream()
    {
        return this;
    }

    asn1outputstream getdlsubstream()
    {
        return this;
    }
}
