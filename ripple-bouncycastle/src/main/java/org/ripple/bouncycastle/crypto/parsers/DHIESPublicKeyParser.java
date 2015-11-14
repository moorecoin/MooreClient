package org.ripple.bouncycastle.crypto.parsers;

import java.io.ioexception;
import java.io.inputstream;
import java.math.biginteger;

import org.ripple.bouncycastle.crypto.keyparser;
import org.ripple.bouncycastle.crypto.params.asymmetrickeyparameter;
import org.ripple.bouncycastle.crypto.params.dhparameters;
import org.ripple.bouncycastle.crypto.params.dhpublickeyparameters;

public class dhiespublickeyparser
    implements keyparser
{
    private dhparameters dhparams;

    public dhiespublickeyparser(dhparameters dhparams)
    {
        this.dhparams = dhparams;
    }

    public asymmetrickeyparameter readkey(inputstream stream)
        throws ioexception
    {
        byte[] v = new byte[(dhparams.getp().bitlength() + 7) / 8];

        stream.read(v, 0, v.length);

        return new dhpublickeyparameters(new biginteger(1, v), dhparams);
    }
}
