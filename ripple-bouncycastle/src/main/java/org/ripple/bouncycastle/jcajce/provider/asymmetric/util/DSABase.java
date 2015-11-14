package org.ripple.bouncycastle.jcajce.provider.asymmetric.util;

import java.math.biginteger;
import java.security.signatureexception;
import java.security.signaturespi;
import java.security.spec.algorithmparameterspec;

import org.ripple.bouncycastle.asn1.pkcs.pkcsobjectidentifiers;
import org.ripple.bouncycastle.asn1.x509.x509objectidentifiers;
import org.ripple.bouncycastle.crypto.dsa;
import org.ripple.bouncycastle.crypto.digest;

public abstract class dsabase
    extends signaturespi
    implements pkcsobjectidentifiers, x509objectidentifiers
{
    protected digest digest;
    protected dsa                     signer;
    protected dsaencoder              encoder;

    protected dsabase(
        digest                  digest,
        dsa                     signer,
        dsaencoder              encoder)
    {
        this.digest = digest;
        this.signer = signer;
        this.encoder = encoder;
    }

    protected void engineupdate(
        byte    b)
        throws signatureexception
    {
        digest.update(b);
    }

    protected void engineupdate(
        byte[]  b,
        int     off,
        int     len) 
        throws signatureexception
    {
        digest.update(b, off, len);
    }

    protected byte[] enginesign()
        throws signatureexception
    {
        byte[]  hash = new byte[digest.getdigestsize()];

        digest.dofinal(hash, 0);

        try
        {
            biginteger[]    sig = signer.generatesignature(hash);

            return encoder.encode(sig[0], sig[1]);
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
        byte[]  hash = new byte[digest.getdigestsize()];

        digest.dofinal(hash, 0);

        biginteger[]    sig;

        try
        {
            sig = encoder.decode(sigbytes);
        }
        catch (exception e)
        {
            throw new signatureexception("error decoding signature bytes.");
        }

        return signer.verifysignature(hash, sig[0], sig[1]);
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
        string  param,
        object  value)
    {
        throw new unsupportedoperationexception("enginesetparameter unsupported");
    }

    /**
     * @deprecated
     */
    protected object enginegetparameter(
        string      param)
    {
        throw new unsupportedoperationexception("enginesetparameter unsupported");
    }
}
