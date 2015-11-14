package org.ripple.bouncycastle.asn1;

import java.io.ioexception;

public class berapplicationspecificparser
    implements asn1applicationspecificparser
{
    private final int tag;
    private final asn1streamparser parser;

    berapplicationspecificparser(int tag, asn1streamparser parser)
    {
        this.tag = tag;
        this.parser = parser;
    }

    public asn1encodable readobject()
        throws ioexception
    {
        return parser.readobject();
    }

    public asn1primitive getloadedobject()
        throws ioexception
    {
         return new berapplicationspecific(tag, parser.readvector());
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
