package org.ripple.bouncycastle.asn1;

import java.io.ioexception;
import java.util.enumeration;

/**
 * note: this class is for processing der/dl encoded sequences only.
 */
class lazyencodedsequence
    extends asn1sequence
{
    private byte[] encoded;

    lazyencodedsequence(
        byte[] encoded)
        throws ioexception
    {
        this.encoded = encoded;
    }

    private void parse()
    {
        enumeration en = new lazyconstructionenumeration(encoded);

        while (en.hasmoreelements())
        {
            seq.addelement(en.nextelement());
        }

        encoded = null;
    }

    public synchronized asn1encodable getobjectat(int index)
    {
        if (encoded != null)
        {
            parse();
        }

        return super.getobjectat(index);
    }

    public synchronized enumeration getobjects()
    {
        if (encoded == null)
        {
            return super.getobjects();
        }

        return new lazyconstructionenumeration(encoded);
    }

    public synchronized int size()
    {
        if (encoded != null)
        {
            parse();
        }

        return super.size();
    }

    asn1primitive toderobject()
    {
        if (encoded != null)
        {
            parse();
        }

        return super.toderobject();
    }

    asn1primitive todlobject()
    {
        if (encoded != null)
        {
            parse();
        }

        return super.todlobject();
    }

    int encodedlength()
        throws ioexception
    {
        if (encoded != null)
        {
            return 1 + streamutil.calculatebodylength(encoded.length) + encoded.length;
        }
        else
        {
            return super.todlobject().encodedlength();
        }
    }

    void encode(
        asn1outputstream out)
        throws ioexception
    {
        if (encoded != null)
        {
            out.writeencoded(bertags.sequence | bertags.constructed, encoded);
        }
        else
        {
            super.todlobject().encode(out);
        }
    }
}
