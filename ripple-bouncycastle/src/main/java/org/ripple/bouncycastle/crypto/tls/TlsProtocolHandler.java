package org.ripple.bouncycastle.crypto.tls;

import java.io.inputstream;
import java.io.outputstream;
import java.security.securerandom;

/**
 * @deprecated use tlsclientprotocol instead
 */
public class tlsprotocolhandler
    extends tlsclientprotocol
{

    public tlsprotocolhandler(inputstream is, outputstream os)
    {
        super(is, os);
    }

    public tlsprotocolhandler(inputstream is, outputstream os, securerandom sr)
    {
        super(is, os, sr);
    }
}
