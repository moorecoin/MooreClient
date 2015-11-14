package org.ripple.bouncycastle.crypto.tls;

import java.io.outputstream;

public class tlsnullcompression
    implements tlscompression
{
    public outputstream compress(outputstream output)
    {
        return output;
    }

    public outputstream decompress(outputstream output)
    {
        return output;
    }
}
