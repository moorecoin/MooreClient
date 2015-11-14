package org.ripple.bouncycastle.jcajce.provider.symmetric.util;

import java.security.algorithmparameters;
import java.security.invalidalgorithmparameterexception;
import java.security.invalidkeyexception;
import java.security.key;
import java.security.keyfactory;
import java.security.nosuchalgorithmexception;
import java.security.nosuchproviderexception;
import java.security.privatekey;
import java.security.securerandom;
import java.security.spec.algorithmparameterspec;
import java.security.spec.invalidkeyspecexception;
import java.security.spec.pkcs8encodedkeyspec;
import java.security.spec.x509encodedkeyspec;

import javax.crypto.badpaddingexception;
import javax.crypto.cipher;
import javax.crypto.cipherspi;
import javax.crypto.illegalblocksizeexception;
import javax.crypto.nosuchpaddingexception;
import javax.crypto.shortbufferexception;
import javax.crypto.spec.ivparameterspec;
import javax.crypto.spec.pbeparameterspec;
import javax.crypto.spec.rc2parameterspec;
import javax.crypto.spec.rc5parameterspec;
import javax.crypto.spec.secretkeyspec;

import org.ripple.bouncycastle.asn1.pkcs.privatekeyinfo;
import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.invalidciphertextexception;
import org.ripple.bouncycastle.crypto.wrapper;
import org.ripple.bouncycastle.crypto.params.keyparameter;
import org.ripple.bouncycastle.crypto.params.parameterswithiv;
import org.ripple.bouncycastle.jce.provider.bouncycastleprovider;

public abstract class basewrapcipher
    extends cipherspi
    implements pbe
{
    //
    // specs we can handle.
    //
    private class[]                 availablespecs =
                                    {
                                        ivparameterspec.class,
                                        pbeparameterspec.class,
                                        rc2parameterspec.class,
                                        rc5parameterspec.class
                                    };

    protected int                     pbetype = pkcs12;
    protected int                     pbehash = sha1;
    protected int                     pbekeysize;
    protected int                     pbeivsize;

    protected algorithmparameters     engineparams = null;

    protected wrapper                 wrapengine = null;

    private int                       ivsize;
    private byte[]                    iv;

    protected basewrapcipher()
    {
    }

    protected basewrapcipher(
        wrapper wrapengine)
    {
        this(wrapengine, 0);
    }

    protected basewrapcipher(
        wrapper wrapengine,
        int ivsize)
    {
        this.wrapengine = wrapengine;
        this.ivsize = ivsize;
    }

    protected int enginegetblocksize()
    {
        return 0;
    }

    protected byte[] enginegetiv()
    {
        return (byte[])iv.clone();
    }

    protected int enginegetkeysize(
        key     key)
    {
        return key.getencoded().length;
    }

    protected int enginegetoutputsize(
        int     inputlen)
    {
        return -1;
    }

    protected algorithmparameters enginegetparameters()
    {
        return null;
    }

    protected void enginesetmode(
        string  mode)
        throws nosuchalgorithmexception
    {
        throw new nosuchalgorithmexception("can't support mode " + mode);
    }

    protected void enginesetpadding(
        string  padding)
    throws nosuchpaddingexception
    {
        throw new nosuchpaddingexception("padding " + padding + " unknown.");
    }

    protected void engineinit(
        int                     opmode,
        key                     key,
        algorithmparameterspec  params,
        securerandom            random)
    throws invalidkeyexception, invalidalgorithmparameterexception
    {
        cipherparameters        param;

        if (key instanceof bcpbekey)
        {
            bcpbekey k = (bcpbekey)key;

            if (params instanceof pbeparameterspec)
            {
                param = pbe.util.makepbeparameters(k, params, wrapengine.getalgorithmname());
            }
            else if (k.getparam() != null)
            {
                param = k.getparam();
            }
            else
            {
                throw new invalidalgorithmparameterexception("pbe requires pbe parameters to be set.");
            }
        }
        else
        {
            param = new keyparameter(key.getencoded());
        }

        if (params instanceof ivparameterspec)
        {
            ivparameterspec iv = (ivparameterspec) params;
            param = new parameterswithiv(param, iv.getiv());
        }

        if (param instanceof keyparameter && ivsize != 0)
        {
            iv = new byte[ivsize];
            random.nextbytes(iv);
            param = new parameterswithiv(param, iv);
        }

        switch (opmode)
        {
        case cipher.wrap_mode:
            wrapengine.init(true, param);
            break;
        case cipher.unwrap_mode:
            wrapengine.init(false, param);
            break;
        case cipher.encrypt_mode:
        case cipher.decrypt_mode:
            throw new illegalargumentexception("engine only valid for wrapping");
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
                    // try next spec
                }
            }

            if (paramspec == null)
            {
                throw new invalidalgorithmparameterexception("can't handle parameter " + params.tostring());
            }
        }

        engineparams = params;
        engineinit(opmode, key, paramspec, random);
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
            throw new illegalargumentexception(e.getmessage());
        }
    }

    protected byte[] engineupdate(
        byte[]  input,
        int     inputoffset,
        int     inputlen)
    {
        throw new runtimeexception("not supported for wrapping");
    }

    protected int engineupdate(
        byte[]  input,
        int     inputoffset,
        int     inputlen,
        byte[]  output,
        int     outputoffset)
        throws shortbufferexception
    {
        throw new runtimeexception("not supported for wrapping");
    }

    protected byte[] enginedofinal(
        byte[]  input,
        int     inputoffset,
        int     inputlen)
        throws illegalblocksizeexception, badpaddingexception
    {
        return null;
    }

    protected int enginedofinal(
        byte[]  input,
        int     inputoffset,
        int     inputlen,
        byte[]  output,
        int     outputoffset)
        throws illegalblocksizeexception, badpaddingexception, shortbufferexception
    {
        return 0;
    }

    protected byte[] enginewrap(
        key     key)
    throws illegalblocksizeexception, invalidkeyexception
    {
        byte[] encoded = key.getencoded();
        if (encoded == null)
        {
            throw new invalidkeyexception("cannot wrap key, null encoding.");
        }

        try
        {
            if (wrapengine == null)
            {
                return enginedofinal(encoded, 0, encoded.length);
            }
            else
            {
                return wrapengine.wrap(encoded, 0, encoded.length);
            }
        }
        catch (badpaddingexception e)
        {
            throw new illegalblocksizeexception(e.getmessage());
        }
    }

    protected key engineunwrap(
        byte[]  wrappedkey,
        string  wrappedkeyalgorithm,
        int     wrappedkeytype)
    throws invalidkeyexception, nosuchalgorithmexception
    {
        byte[] encoded;
        try
        {
            if (wrapengine == null)
            {
                encoded = enginedofinal(wrappedkey, 0, wrappedkey.length);
            }
            else
            {
                encoded = wrapengine.unwrap(wrappedkey, 0, wrappedkey.length);
            }
        }
        catch (invalidciphertextexception e)
        {
            throw new invalidkeyexception(e.getmessage());
        }
        catch (badpaddingexception e)
        {
            throw new invalidkeyexception(e.getmessage());
        }
        catch (illegalblocksizeexception e2)
        {
            throw new invalidkeyexception(e2.getmessage());
        }

        if (wrappedkeytype == cipher.secret_key)
        {
            return new secretkeyspec(encoded, wrappedkeyalgorithm);
        }
        else if (wrappedkeyalgorithm.equals("") && wrappedkeytype == cipher.private_key)
        {
            /*
             * the caller doesn't know the algorithm as it is part of
             * the encrypted data.
             */
            try
            {
                privatekeyinfo       in = privatekeyinfo.getinstance(encoded);

                privatekey privkey = bouncycastleprovider.getprivatekey(in);

                if (privkey != null)
                {
                    return privkey;
                }
                else
                {
                    throw new invalidkeyexception("algorithm " + in.getprivatekeyalgorithm().getalgorithm() + " not supported");
                }
            }
            catch (exception e)
            {
                throw new invalidkeyexception("invalid key encoding.");
            }
        }
        else
        {
            try
            {
                keyfactory kf = keyfactory.getinstance(wrappedkeyalgorithm, bouncycastleprovider.provider_name);

                if (wrappedkeytype == cipher.public_key)
                {
                    return kf.generatepublic(new x509encodedkeyspec(encoded));
                }
                else if (wrappedkeytype == cipher.private_key)
                {
                    return kf.generateprivate(new pkcs8encodedkeyspec(encoded));
                }
            }
            catch (nosuchproviderexception e)
            {
                throw new invalidkeyexception("unknown key type " + e.getmessage());
            }
            catch (invalidkeyspecexception e2)
            {
                throw new invalidkeyexception("unknown key type " + e2.getmessage());
            }

            throw new invalidkeyexception("unknown key type " + wrappedkeytype);
        }
    }

}
