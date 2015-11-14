package org.ripple.bouncycastle.jcajce.provider.symmetric.util;

import java.security.invalidalgorithmparameterexception;
import java.security.invalidkeyexception;
import java.security.key;
import java.security.spec.algorithmparameterspec;

import javax.crypto.macspi;
import javax.crypto.spec.ivparameterspec;
import javax.crypto.spec.pbeparameterspec;

import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.mac;
import org.ripple.bouncycastle.crypto.params.keyparameter;
import org.ripple.bouncycastle.crypto.params.parameterswithiv;

public class basemac
    extends macspi implements pbe
{
    private mac macengine;

    private int                     pbetype = pkcs12;
    private int                     pbehash = sha1;
    private int                     keysize = 160;

    protected basemac(
        mac macengine)
    {
        this.macengine = macengine;
    }

    protected basemac(
        mac macengine,
        int pbetype,
        int pbehash,
        int keysize)
    {
        this.macengine = macengine;
        this.pbetype = pbetype;
        this.pbehash = pbehash;
        this.keysize = keysize;
    }

    protected void engineinit(
        key                     key,
        algorithmparameterspec  params)
        throws invalidkeyexception, invalidalgorithmparameterexception
    {
        cipherparameters        param;

        if (key == null)
        {
            throw new invalidkeyexception("key is null");
        }

        if (key instanceof bcpbekey)
        {
            bcpbekey k = (bcpbekey)key;

            if (k.getparam() != null)
            {
                param = k.getparam();
            }
            else if (params instanceof pbeparameterspec)
            {
                param = pbe.util.makepbemacparameters(k, params);
            }
            else
            {
                throw new invalidalgorithmparameterexception("pbe requires pbe parameters to be set.");
            }
        }
        else if (params instanceof ivparameterspec)
        {
            param = new parameterswithiv(new keyparameter(key.getencoded()), ((ivparameterspec)params).getiv());
        }
        else if (params == null)
        {
            param = new keyparameter(key.getencoded());
        }
        else
        {
            throw new invalidalgorithmparameterexception("unknown parameter type.");
        }

        macengine.init(param);
    }

    protected int enginegetmaclength() 
    {
        return macengine.getmacsize();
    }

    protected void enginereset() 
    {
        macengine.reset();
    }

    protected void engineupdate(
        byte    input) 
    {
        macengine.update(input);
    }

    protected void engineupdate(
        byte[]  input,
        int     offset,
        int     len) 
    {
        macengine.update(input, offset, len);
    }

    protected byte[] enginedofinal() 
    {
        byte[]  out = new byte[enginegetmaclength()];

        macengine.dofinal(out, 0);

        return out;
    }
}
