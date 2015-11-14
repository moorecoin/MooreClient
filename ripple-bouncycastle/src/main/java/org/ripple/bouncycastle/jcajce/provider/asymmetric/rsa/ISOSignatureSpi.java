package org.ripple.bouncycastle.jcajce.provider.asymmetric.rsa;

import java.security.invalidkeyexception;
import java.security.privatekey;
import java.security.publickey;
import java.security.signatureexception;
import java.security.signaturespi;
import java.security.interfaces.rsaprivatekey;
import java.security.interfaces.rsapublickey;
import java.security.spec.algorithmparameterspec;

import org.ripple.bouncycastle.crypto.asymmetricblockcipher;
import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.digest;
import org.ripple.bouncycastle.crypto.digests.md5digest;
import org.ripple.bouncycastle.crypto.digests.ripemd160digest;
import org.ripple.bouncycastle.crypto.digests.sha1digest;
import org.ripple.bouncycastle.crypto.engines.rsablindedengine;
import org.ripple.bouncycastle.crypto.signers.iso9796d2signer;

public class isosignaturespi
    extends signaturespi
{
    private iso9796d2signer signer;

    protected isosignaturespi(
        digest digest,
        asymmetricblockcipher cipher)
    {
        signer = new iso9796d2signer(cipher, digest, true);
    }

    protected void engineinitverify(
        publickey publickey)
        throws invalidkeyexception
    {
        cipherparameters param = rsautil.generatepublickeyparameter((rsapublickey)publickey);

        signer.init(false, param);
    }

    protected void engineinitsign(
        privatekey privatekey)
        throws invalidkeyexception
    {
        cipherparameters param = rsautil.generateprivatekeyparameter((rsaprivatekey)privatekey);

        signer.init(true, param);
    }

    protected void engineupdate(
        byte    b)
        throws signatureexception
    {
        signer.update(b);
    }

    protected void engineupdate(
        byte[]  b,
        int     off,
        int     len) 
        throws signatureexception
    {
        signer.update(b, off, len);
    }

    protected byte[] enginesign()
        throws signatureexception
    {
        try
        {
            byte[]  sig = signer.generatesignature();

            return sig;
        }
        catch (exception e)
        {
            throw new signatureexception(e.tostring());
        }
    }

    protected boolean engineverify(
        byte[]  sigbytes) 
        throws signatureexception
    {
        boolean yes = signer.verifysignature(sigbytes);

        return yes;
    }

    protected void enginesetparameter(
        algorithmparameterspec params)
    {
        throw new unsupportedoperationexception("enginesetparameter unsupported");
    }

    /**
     * @deprecated replaced with <a href = "#enginesetparameter(java.security.spec.algorithmparameterspec)">
     */
    protected void enginesetparameter(
        string param,
        object value)
    {
        throw new unsupportedoperationexception("enginesetparameter unsupported");
    }

    /**
     * @deprecated
     */
    protected object enginegetparameter(
        string param)
    {
        throw new unsupportedoperationexception("enginesetparameter unsupported");
    }

    static public class sha1withrsaencryption
        extends isosignaturespi
    {
        public sha1withrsaencryption()
        {
            super(new sha1digest(), new rsablindedengine());
        }
    }

    static public class md5withrsaencryption
        extends isosignaturespi
    {
        public md5withrsaencryption()
        {
            super(new md5digest(), new rsablindedengine());
        }
    }

    static public class ripemd160withrsaencryption
        extends isosignaturespi
    {
        public ripemd160withrsaencryption()
        {
            super(new ripemd160digest(), new rsablindedengine());
        }
    }
}
