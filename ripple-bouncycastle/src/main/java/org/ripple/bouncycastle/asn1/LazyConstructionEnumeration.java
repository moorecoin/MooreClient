package org.ripple.bouncycastle.asn1;

import java.io.ioexception;
import java.util.enumeration;

class lazyconstructionenumeration
    implements enumeration
{
    private asn1inputstream ain;
    private object          nextobj;

    public lazyconstructionenumeration(byte[] encoded)
    {
        ain = new asn1inputstream(encoded, true);
        nextobj = readobject();
    }

    public boolean hasmoreelements()
    {
        return nextobj != null;
    }

    public object nextelement()
    {
        object o = nextobj;

        nextobj = readobject();

        return o;
    }

    private object readobject()
    {
        try
        {
            return ain.readobject();
        }
        catch (ioexception e)
        {
            throw new asn1parsingexception("malformed der construction: " + e, e);
        }
    }
}
