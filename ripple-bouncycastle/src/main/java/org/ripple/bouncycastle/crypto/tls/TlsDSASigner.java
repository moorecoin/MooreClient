package org.ripple.bouncycastle.crypto.tls;

import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.cryptoexception;
import org.ripple.bouncycastle.crypto.dsa;
import org.ripple.bouncycastle.crypto.digest;
import org.ripple.bouncycastle.crypto.signer;
import org.ripple.bouncycastle.crypto.digests.nulldigest;
import org.ripple.bouncycastle.crypto.digests.sha1digest;
import org.ripple.bouncycastle.crypto.params.asymmetrickeyparameter;
import org.ripple.bouncycastle.crypto.params.parameterswithrandom;
import org.ripple.bouncycastle.crypto.signers.dsadigestsigner;

public abstract class tlsdsasigner
    extends abstracttlssigner
{

    public byte[] generaterawsignature(asymmetrickeyparameter privatekey, byte[] md5andsha1)
        throws cryptoexception
    {

        // note: only use the sha1 part of the hash
        signer signer = makesigner(new nulldigest(), true,
            new parameterswithrandom(privatekey, this.context.getsecurerandom()));
        signer.update(md5andsha1, 16, 20);
        return signer.generatesignature();
    }

    public boolean verifyrawsignature(byte[] sigbytes, asymmetrickeyparameter publickey, byte[] md5andsha1)
        throws cryptoexception
    {

        // note: only use the sha1 part of the hash
        signer signer = makesigner(new nulldigest(), false, publickey);
        signer.update(md5andsha1, 16, 20);
        return signer.verifysignature(sigbytes);
    }

    public signer createsigner(asymmetrickeyparameter privatekey)
    {
        return makesigner(new sha1digest(), true, new parameterswithrandom(privatekey, this.context.getsecurerandom()));
    }

    public signer createverifyer(asymmetrickeyparameter publickey)
    {
        return makesigner(new sha1digest(), false, publickey);
    }

    protected signer makesigner(digest d, boolean forsigning, cipherparameters cp)
    {
        signer s = new dsadigestsigner(createdsaimpl(), d);
        s.init(forsigning, cp);
        return s;
    }

    protected abstract dsa createdsaimpl();
}
