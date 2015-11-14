package org.ripple.bouncycastle.asn1;

import java.io.ioexception;
import java.io.inputstream;

public class deroctetstringparser
    implements asn1octetstringparser
{
    private definitelengthinputstream stream;

    deroctetstringparser(
        definitelengthinputstream stream)
    {
        this.stream = stream;
    }

    public inputstream getoctetstream()
    {
        return stream;
    }

    public asn1primitive getloadedobject()
        throws ioexception
    {
        return new deroctetstring(stream.tobytearray());
    }
    
    public asn1primitive toasn1primitive()
    {
        try
        {
            return getloadedobject();
        }
        catch (ioexception e)
        {
            throw new asn1parsingexception("ioexception converting stream to byte array: " + e.getmessage(), e);
        }
    }
}
