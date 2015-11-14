package org.ripple.bouncycastle.asn1;

import java.io.ioexception;
import java.io.inputstream;

import org.ripple.bouncycastle.util.io.streams;

public class beroctetstringparser
    implements asn1octetstringparser
{
    private asn1streamparser _parser;

    beroctetstringparser(
        asn1streamparser parser)
    {
        _parser = parser;
    }

    public inputstream getoctetstream()
    {
        return new constructedoctetstream(_parser);
    }

    public asn1primitive getloadedobject()
        throws ioexception
    {
        return new beroctetstring(streams.readall(getoctetstream()));
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
