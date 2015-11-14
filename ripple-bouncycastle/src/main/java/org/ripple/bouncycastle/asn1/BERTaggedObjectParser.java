package org.ripple.bouncycastle.asn1;

import java.io.ioexception;

public class bertaggedobjectparser
    implements asn1taggedobjectparser
{
    private boolean _constructed;
    private int _tagnumber;
    private asn1streamparser _parser;

    bertaggedobjectparser(
        boolean             constructed,
        int                 tagnumber,
        asn1streamparser    parser)
    {
        _constructed = constructed;
        _tagnumber = tagnumber;
        _parser = parser;
    }

    public boolean isconstructed()
    {
        return _constructed;
    }

    public int gettagno()
    {
        return _tagnumber;
    }

    public asn1encodable getobjectparser(
        int     tag,
        boolean isexplicit)
        throws ioexception
    {
        if (isexplicit)
        {
            if (!_constructed)
            {
                throw new ioexception("explicit tags must be constructed (see x.690 8.14.2)");
            }
            return _parser.readobject();
        }

        return _parser.readimplicit(_constructed, tag);
    }

    public asn1primitive getloadedobject()
        throws ioexception
    {
        return _parser.readtaggedobject(_constructed, _tagnumber);
    }

    public asn1primitive toasn1primitive()
    {
        try
        {
            return this.getloadedobject();
        }
        catch (ioexception e)
        {
            throw new asn1parsingexception(e.getmessage());
        }
    }
}
