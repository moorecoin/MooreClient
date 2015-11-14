package org.ripple.bouncycastle.asn1;

import java.io.ioexception;
import java.io.outputstream;

public class beroutputstream
    extends deroutputstream
{
    public beroutputstream(
        outputstream    os)
    {
        super(os);
    }

    public void writeobject(
        object    obj)
        throws ioexception
    {
        if (obj == null)
        {
            writenull();
        }
        else if (obj instanceof asn1primitive)
        {
            ((asn1primitive)obj).encode(this);
        }
        else if (obj instanceof asn1encodable)
        {
            ((asn1encodable)obj).toasn1primitive().encode(this);
        }
        else
        {
            throw new ioexception("object not berencodable");
        }
    }
}
