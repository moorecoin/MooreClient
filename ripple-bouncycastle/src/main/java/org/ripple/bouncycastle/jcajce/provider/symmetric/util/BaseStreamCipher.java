package org.ripple.bouncycastle.jcajce.provider.symmetric.util;

import java.security.algorithmparameters;
import java.security.invalidalgorithmparameterexception;
import java.security.invalidkeyexception;
import java.security.key;
import java.security.securerandom;
import java.security.spec.algorithmparameterspec;

import javax.crypto.cipher;
import javax.crypto.nosuchpaddingexception;
import javax.crypto.secretkey;
import javax.crypto.shortbufferexception;
import javax.crypto.spec.ivparameterspec;
import javax.crypto.spec.pbeparameterspec;
import javax.crypto.spec.rc2parameterspec;
import javax.crypto.spec.rc5parameterspec;

import org.ripple.bouncycastle.crypto.blockcipher;
import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.datalengthexception;
import org.ripple.bouncycastle.crypto.streamblockcipher;
import org.ripple.bouncycastle.crypto.streamcipher;
import org.ripple.bouncycastle.crypto.params.keyparameter;
import org.ripple.bouncycastle.crypto.params.parameterswithiv;
import org.ripple.bouncycastle.jce.provider.bouncycastleprovider;

public class basestreamcipher
    extends basewrapcipher
    implements pbe
{
    //
    // specs we can handle.
    //
    private class[]                 availablespecs =
                                    {
                                        rc2parameterspec.class,
                                        rc5parameterspec.class,
                                        ivparameterspec.class,
                                        pbeparameterspec.class
                                    };

    private streamcipher       cipher;
    private parameterswithiv   ivparam;

    private int                     ivlength = 0;

    private pbeparameterspec        pbespec = null;
    private string                  pbealgorithm = null;

    protected basestreamcipher(
        streamcipher engine,
        int ivlength)
    {
        cipher = engine;
        this.ivlength = ivlength;
    }

    protected basestreamcipher(
        blockcipher engine,
        int ivlength)
    {
        this.ivlength = ivlength;

        cipher = new streamblockcipher(engine);
    }

    protected int enginegetblocksize()
    {
        return 0;
    }

    protected byte[] enginegetiv()
    {
        return (ivparam != null) ? ivparam.getiv() : null;
    }

    protected int enginegetkeysize(
        key     key)
    {
        return key.getencoded().length * 8;
    }

    protected int enginegetoutputsize(
        int     inputlen)
    {
        return inputlen;
    }

    protected algorithmparameters enginegetparameters()
    {
        if (engineparams == null)
        {
            if (pbespec != null)
            {
                try
                {
                    algorithmparameters engineparams = algorithmparameters.getinstance(pbealgorithm, bouncycastleprovider.provider_name);
                    engineparams.init(pbespec);

                    return engineparams;
                }
                catch (exception e)
                {
                    return null;
                }
            }
        }

        return engineparams;
    }

    /**
     * should never be called.
     */
    protected void enginesetmode(
        string  mode)
    {
        if (!mode.equalsignorecase("ecb"))
        {
            throw new illegalargumentexception("can't support mode " + mode);
        }
    }

    /**
     * should never be called.
     */
    protected void enginesetpadding(
        string  padding)
    throws nosuchpaddingexception
    {
        if (!padding.equalsignorecase("nopadding"))
        {
            throw new nosuchpaddingexception("padding " + padding + " unknown.");
        }
    }

    protected void engineinit(
        int                     opmode,
        key                     key,
        algorithmparameterspec  params,
        securerandom            random)
        throws invalidkeyexception, invalidalgorithmparameterexception
    {
        cipherparameters        param;

        this.pbespec = null;
        this.pbealgorithm = null;

        this.engineparams = null;

        //
        // basic key check
        //
        if (!(key instanceof secretkey))
        {
            throw new invalidkeyexception("key for algorithm " + key.getalgorithm() + " not suitable for symmetric enryption.");
        }

        if (key instanceof bcpbekey)
        {
            bcpbekey k = (bcpbekey)key;

            if (k.getoid() != null)
            {
                pbealgorithm = k.getoid().getid();
            }
            else
            {
                pbealgorithm = k.getalgorithm();
            }

            if (k.getparam() != null)
            {
                param = k.getparam();
                pbespec = new pbeparameterspec(k.getsalt(), k.getiterationcount());
            }
            else if (params instanceof pbeparameterspec)
            {
                param = pbe.util.makepbeparameters(k, params, cipher.getalgorithmname());
                pbespec = (pbeparameterspec)params;
            }
            else
            {
                throw new invalidalgorithmparameterexception("pbe requires pbe parameters to be set.");
            }
            
            if (k.getivsize() != 0)
            {
                ivparam = (parameterswithiv)param;
            }
        }
        else if (params == null)
        {
            param = new keyparameter(key.getencoded());
        }
        else if (params instanceof ivparameterspec)
        {
            param = new parameterswithiv(new keyparameter(key.getencoded()), ((ivparameterspec)params).getiv());
            ivparam = (parameterswithiv)param;
        }
        else
        {
            throw new illegalargumentexception("unknown parameter type.");
        }

        if ((ivlength != 0) && !(param instanceof parameterswithiv))
        {
            securerandom    ivrandom = random;

            if (ivrandom == null)
            {
                ivrandom = new securerandom();
            }

            if ((opmode == cipher.encrypt_mode) || (opmode == cipher.wrap_mode))
            {
                byte[]  iv = new byte[ivlength];

                ivrandom.nextbytes(iv);
                param = new parameterswithiv(param, iv);
                ivparam = (parameterswithiv)param;
            }
            else
            {
                throw new invalidalgorithmparameterexception("no iv set when one expected");
            }
        }

        switch (opmode)
        {
        case cipher.encrypt_mode:
        case cipher.wrap_mode:
            cipher.init(true, param);
            break;
        case cipher.decrypt_mode:
        case cipher.unwrap_mode:
            cipher.init(false, param);
            break;
        default:
            system.out.println("eeek!");
        }
    }

    protected void engineinit(
        int                 opmode,
        key                 key,
        algorithmparameters params,
        securerandom        random) 
        throws invalidkeyexception, invalidalgorithmparameterexception
    {
        algorithmparameterspec  paramspec = null;

        if (params != null)
        {
            for (int i = 0; i != availablespecs.length; i++)
            {
                try
                {
                    paramspec = params.getparameterspec(availablespecs[i]);
                    break;
                }
                catch (exception e)
                {
                    continue;
                }
            }

            if (paramspec == null)
            {
                throw new invalidalgorithmparameterexception("can't handle parameter " + params.tostring());
            }
        }

        engineinit(opmode, key, paramspec, random);
        engineparams = params;
    }

    protected void engineinit(
        int                 opmode,
        key                 key,
        securerandom        random) 
        throws invalidkeyexception
    {
        try
        {
            engineinit(opmode, key, (algorithmparameterspec)null, random);
        }
        catch (invalidalgorithmparameterexception e)
        {
            throw new invalidkeyexception(e.getmessage());
        }
    }

    protected byte[] engineupdate(
        byte[]  input,
        int     inputoffset,
        int     inputlen) 
    {
        byte[]  out = new byte[inputlen];

        cipher.processbytes(input, inputoffset, inputlen, out, 0);

        return out;
    }

    protected int engineupdate(
        byte[]  input,
        int     inputoffset,
        int     inputlen,
        byte[]  output,
        int     outputoffset) 
        throws shortbufferexception 
    {
        try
        {
        cipher.processbytes(input, inputoffset, inputlen, output, outputoffset);

        return inputlen;
        }
        catch (datalengthexception e)
        {
            throw new shortbufferexception(e.getmessage());
        }
    }

    protected byte[] enginedofinal(
        byte[]  input,
        int     inputoffset,
        int     inputlen) 
    {
        if (inputlen != 0)
        {
            byte[] out = engineupdate(input, inputoffset, inputlen);

            cipher.reset();
            
            return out;
        }

        cipher.reset();
        
        return new byte[0];
    }

    protected int enginedofinal(
        byte[]  input,
        int     inputoffset,
        int     inputlen,
        byte[]  output,
        int     outputoffset) 
    {
        if (inputlen != 0)
        {
            cipher.processbytes(input, inputoffset, inputlen, output, outputoffset);
        }

        cipher.reset();
        
        return inputlen;
    }
}
