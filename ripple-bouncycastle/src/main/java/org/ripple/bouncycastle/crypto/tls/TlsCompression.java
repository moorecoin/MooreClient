package org.ripple.bouncycastle.crypto.tls;

import java.io.outputstream;

public interface tlscompression
{
    outputstream compress(outputstream output);

    outputstream decompress(outputstream output);
}
