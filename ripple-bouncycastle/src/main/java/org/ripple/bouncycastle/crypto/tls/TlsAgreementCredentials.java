package org.ripple.bouncycastle.crypto.tls;

import java.io.ioexception;

import org.ripple.bouncycastle.crypto.params.asymmetrickeyparameter;

public interface tlsagreementcredentials
    extends tlscredentials
{

    byte[] generateagreement(asymmetrickeyparameter peerpublickey)
        throws ioexception;
}
