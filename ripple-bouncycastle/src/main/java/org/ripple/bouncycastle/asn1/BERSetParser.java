package org.ripple.bouncycastle.asn1;

import java.io.ioexception;

public class bersetparser
    implements asn1setparser
{
    private asn1streamparser _parser;

    bersetparser(asn1streamparser parser)
    {
        this._parser = parser;
    }

    public asn1encodable readobject()
        throws ioexception
    {
        return _parser.readobject();
    }

    public asn1primitive getloadedobject()
        throws ioexception
    {
        return new berset(_parser.readvector());
    }

    public asn1primitive toasn1primitive()
    {
        try
        {
            return getloadedobject();
        }
        catch (ioexception e)
        {
            throw new asn1parsingexception(e.getmessage(), e);
        }
    }
}
