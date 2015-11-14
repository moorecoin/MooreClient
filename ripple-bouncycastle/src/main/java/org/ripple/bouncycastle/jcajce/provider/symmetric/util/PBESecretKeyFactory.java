package org.ripple.bouncycastle.jcajce.provider.symmetric.util;

import java.security.spec.invalidkeyspecexception;
import java.security.spec.keyspec;

import javax.crypto.secretkey;
import javax.crypto.spec.pbekeyspec;

import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.crypto.cipherparameters;

public class pbesecretkeyfactory
    extends basesecretkeyfactory
    implements pbe
{
    private boolean forcipher;
    private int scheme;
    private int digest;
    private int keysize;
    private int ivsize;

    public pbesecretkeyfactory(
        string algorithm,
        asn1objectidentifier oid,
        boolean forcipher,
        int scheme,
        int digest,
        int keysize,
        int ivsize)
    {
        super(algorithm, oid);

        this.forcipher = forcipher;
        this.scheme = scheme;
        this.digest = digest;
        this.keysize = keysize;
        this.ivsize = ivsize;
    }

    protected secretkey enginegeneratesecret(
        keyspec keyspec)
        throws invalidkeyspecexception
    {
        if (keyspec instanceof pbekeyspec)
        {
            pbekeyspec pbespec = (pbekeyspec)keyspec;
            cipherparameters param;

            if (pbespec.getsalt() == null)
            {
                return new bcpbekey(this.algname, this.algoid, scheme, digest, keysize, ivsize, pbespec, null);
            }

            if (forcipher)
            {
                param = pbe.util.makepbeparameters(pbespec, scheme, digest, keysize, ivsize);
            }
            else
            {
                param = pbe.util.makepbemacparameters(pbespec, scheme, digest, keysize);
            }

            return new bcpbekey(this.algname, this.algoid, scheme, digest, keysize, ivsize, pbespec, param);
        }

        throw new invalidkeyspecexception("invalid keyspec");
    }
}
