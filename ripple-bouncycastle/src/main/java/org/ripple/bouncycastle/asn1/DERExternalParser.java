package org.ripple.bouncycastle.asn1;

import java.io.ioexception;

public class derexternalparser
    implements asn1encodable, inmemoryrepresentable
{
    private asn1streamparser _parser;

    /**
     * 
     */
    public derexternalparser(asn1streamparser parser)
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
        try
        {
            return new derexternal(_parser.readvector());
        }
        catch (illegalargumentexception e)
        {
            throw new asn1exception(e.getmessage(), e);
        }
    }
    
    public asn1primitive toasn1primitive()
    {
        try 
        {
            return getloadedobject();
        }
        catch (ioexception ioe) 
        {
            throw new asn1parsingexception("unable to get der object", ioe);
        }
        catch (illegalargumentexception ioe) 
        {
            throw new asn1parsingexception("unable to get der object", ioe);
        }
    }
}
