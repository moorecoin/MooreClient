package org.ripple.bouncycastle.crypto.tls;

import java.io.ioexception;

public class abstracttlscipherfactory
    implements tlscipherfactory
{

    public tlscipher createcipher(tlscontext context, int encryptionalgorithm, int macalgorithm)
        throws ioexception
    {

        throw new tlsfatalalert(alertdescription.internal_error);
    }
}
