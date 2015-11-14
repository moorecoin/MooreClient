package org.ripple.bouncycastle.pqc.jcajce.provider.rainbow;

import java.security.invalidkeyexception;
import java.security.privatekey;
import java.security.publickey;
import java.security.securerandom;
import java.security.signatureexception;
import java.security.spec.algorithmparameterspec;

import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.digest;
import org.ripple.bouncycastle.crypto.digests.sha224digest;
import org.ripple.bouncycastle.crypto.digests.sha256digest;
import org.ripple.bouncycastle.crypto.digests.sha384digest;
import org.ripple.bouncycastle.crypto.digests.sha512digest;
import org.ripple.bouncycastle.crypto.params.parameterswithrandom;
import org.ripple.bouncycastle.pqc.crypto.rainbow.rainbowsigner;

/**
 * rainbow signature class, extending the jce signaturespi.
 */
public class signaturespi
    extends java.security.signaturespi
{
    private digest digest;
    private rainbowsigner signer;
    private securerandom random;

    protected signaturespi(digest digest, rainbowsigner signer)
    {
        this.digest = digest;
        this.signer = signer;
    }

    protected void engineinitverify(publickey publickey)
        throws invalidkeyexception
    {
        cipherparameters param;
        param = rainbowkeystoparams.generatepublickeyparameter(publickey);

        digest.reset();
        signer.init(false, param);
    }

    protected void engineinitsign(privatekey privatekey, securerandom random)
        throws invalidkeyexception
    {
        this.random = random;
        engineinitsign(privatekey);
    }

    protected void engineinitsign(privatekey privatekey)
        throws invalidkeyexception
    {
        cipherparameters param;
        param = rainbowkeystoparams.generateprivatekeyparameter(privatekey);

        if (random != null)
        {
            param = new parameterswithrandom(param, random);
        }

        digest.reset();
        signer.init(true, param);

    }

    protected void engineupdate(byte b)
        throws signatureexception
    {
        digest.update(b);
    }

    protected void engineupdate(byte[] b, int off, int len)
        throws signatureexception
    {
        digest.update(b, off, len);
    }

    protected byte[] enginesign()
        throws signatureexception
    {
        byte[] hash = new byte[digest.getdigestsize()];
        digest.dofinal(hash, 0);
        try
        {
            byte[] sig = signer.generatesignature(hash);

            return sig;
        }
        catch (exception e)
        {
            throw new signatureexception(e.tostring());
        }
    }

    protected boolean engineverify(byte[] sigbytes)
        throws signatureexception
    {
        byte[] hash = new byte[digest.getdigestsize()];
        digest.dofinal(hash, 0);
        return signer.verifysignature(hash, sigbytes);
    }

    protected void enginesetparameter(algorithmparameterspec params)
    {
        throw new unsupportedoperationexception("enginesetparameter unsupported");
    }

    /**
     * @deprecated replaced with <a href =
     *             "#enginesetparameter(java.security.spec.algorithmparameterspec)"
     *             >
     */
    protected void enginesetparameter(string param, object value)
    {
        throw new unsupportedoperationexception("enginesetparameter unsupported");
    }

    /**
     * @deprecated
     */
    protected object enginegetparameter(string param)
    {
        throw new unsupportedoperationexception("enginesetparameter unsupported");
    }


    static public class withsha224
        extends signaturespi
    {
        public withsha224()
        {
            super(new sha224digest(), new rainbowsigner());
        }
    }

    static public class withsha256
        extends signaturespi
    {
        public withsha256()
        {
            super(new sha256digest(), new rainbowsigner());
        }
    }

    static public class withsha384
        extends signaturespi
    {
        public withsha384()
        {
            super(new sha384digest(), new rainbowsigner());
        }
    }

    static public class withsha512
        extends signaturespi
    {
        public withsha512()
        {
            super(new sha512digest(), new rainbowsigner());
        }
    }
}
