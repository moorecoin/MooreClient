package org.ripple.bouncycastle.crypto.tls;

import java.security.securerandom;

class tlsclientcontextimpl
    extends abstracttlscontext
    implements tlsclientcontext
{

    tlsclientcontextimpl(securerandom securerandom, securityparameters securityparameters)
    {
        super(securerandom, securityparameters);
    }

    public boolean isserver()
    {
        return false;
    }
}
