package org.ripple.bouncycastle.crypto.tls;

import java.io.ioexception;

public interface tlscipherfactory
{

    /**
     * see enumeration classes encryptionalgorithm, macalgorithm for appropriate argument values
     */
    tlscipher createcipher(tlscontext context, int encryptionalgorithm, int macalgorithm)
        throws ioexception;
}
