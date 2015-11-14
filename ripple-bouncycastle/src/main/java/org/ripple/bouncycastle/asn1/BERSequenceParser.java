package org.ripple.bouncycastle.asn1;

import java.io.ioexception;

public class bersequenceparser
    implements asn1sequenceparser
{
    private asn1streamparser _parser;

    bersequenceparser(asn1streamparser parser)
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
        return new bersequence(_parser.readvector());
    }
    
    public asn1primitive toasn1primitive()
    {
        try
        {
            return getloadedobject();
        }
        catch (ioexception e)
        {
            throw new illegalstateexception(e.getmessage());
        }
    }
}
