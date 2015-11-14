package org.ripple.bouncycastle.crypto.tls;

import org.ripple.bouncycastle.crypto.cryptoexception;
import org.ripple.bouncycastle.crypto.signer;
import org.ripple.bouncycastle.crypto.params.asymmetrickeyparameter;

public interface tlssigner
{

    void init(tlscontext context);

    byte[] generaterawsignature(asymmetrickeyparameter privatekey, byte[] md5andsha1)
        throws cryptoexception;

    boolean verifyrawsignature(byte[] sigbytes, asymmetrickeyparameter publickey, byte[] md5andsha1)
        throws cryptoexception;

    signer createsigner(asymmetrickeyparameter privatekey);

    signer createverifyer(asymmetrickeyparameter publickey);

    boolean isvalidpublickey(asymmetrickeyparameter publickey);
}
