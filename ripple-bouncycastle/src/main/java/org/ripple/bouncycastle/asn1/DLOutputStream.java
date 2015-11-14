package org.ripple.bouncycastle.asn1;

import java.io.ioexception;
import java.io.outputstream;

/**
 * stream that outputs encoding based on definite length.
 */
public class dloutputstream
    extends asn1outputstream
{
    public dloutputstream(
        outputstream os)
    {
        super(os);
    }

    public void writeobject(
        asn1encodable obj)
        throws ioexception
    {
        if (obj != null)
        {
            obj.toasn1primitive().todlobject().encode(this);
        }
        else
        {
            throw new ioexception("null object detected");
        }
    }
}
