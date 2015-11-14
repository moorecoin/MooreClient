package org.ripple.bouncycastle.crypto.parsers;

import java.io.ioexception;
import java.io.inputstream;

import org.ripple.bouncycastle.crypto.keyparser;
import org.ripple.bouncycastle.crypto.params.asymmetrickeyparameter;
import org.ripple.bouncycastle.crypto.params.ecdomainparameters;
import org.ripple.bouncycastle.crypto.params.ecpublickeyparameters;

public class eciespublickeyparser
    implements keyparser
{
    private ecdomainparameters ecparams;

    public eciespublickeyparser(ecdomainparameters ecparams)
    {
        this.ecparams = ecparams;
    }

    public asymmetrickeyparameter readkey(inputstream stream)
        throws ioexception
    {
        byte[] v;
        int    first = stream.read();

        // decode the public ephemeral key
        switch (first)
        {
        case 0x00: // infinity
            throw new ioexception("sender's public key invalid.");

        case 0x02: // compressed
        case 0x03: // byte length calculated as in ecpoint.getencoded();
            v = new byte[1 + (ecparams.getcurve().getfieldsize()+7)/8];
            break;

        case 0x04: // uncompressed or
        case 0x06: // hybrid
        case 0x07: // byte length calculated as in ecpoint.getencoded();
            v = new byte[1 + 2*((ecparams.getcurve().getfieldsize()+7)/8)];
            break;

        default:
            throw new ioexception("sender's public key has invalid point encoding 0x" + integer.tostring(first, 16));
        }

        v[0] = (byte)first;
        stream.read(v, 1, v.length - 1);

        return new ecpublickeyparameters(ecparams.getcurve().decodepoint(v), ecparams);
    }
}
