package org.ripple.bouncycastle.crypto.tls;

import java.security.securerandom;

class tlsservercontextimpl
    extends abstracttlscontext
    implements tlsservercontext
{

    tlsservercontextimpl(securerandom securerandom, securityparameters securityparameters)
    {
        super(securerandom, securityparameters);
    }

    public boolean isserver()
    {
        return true;
    }
}
