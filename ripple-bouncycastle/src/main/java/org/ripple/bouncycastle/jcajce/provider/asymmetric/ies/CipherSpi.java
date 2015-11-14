package org.ripple.bouncycastle.jcajce.provider.asymmetric.ies;

import java.io.bytearrayoutputstream;
import java.security.algorithmparameters;
import java.security.invalidalgorithmparameterexception;
import java.security.invalidkeyexception;
import java.security.key;
import java.security.securerandom;
import java.security.spec.algorithmparameterspec;

import javax.crypto.badpaddingexception;
import javax.crypto.cipher;
import javax.crypto.illegalblocksizeexception;
import javax.crypto.nosuchpaddingexception;
import javax.crypto.interfaces.dhprivatekey;

import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.invalidciphertextexception;
import org.ripple.bouncycastle.crypto.agreement.dhbasicagreement;
import org.ripple.bouncycastle.crypto.digests.sha1digest;
import org.ripple.bouncycastle.crypto.engines.iesengine;
import org.ripple.bouncycastle.crypto.generators.kdf2bytesgenerator;
import org.ripple.bouncycastle.crypto.macs.hmac;
import org.ripple.bouncycastle.crypto.params.iesparameters;
import org.ripple.bouncycastle.jcajce.provider.asymmetric.util.dhutil;
import org.ripple.bouncycastle.jcajce.provider.asymmetric.util.ecutil;
import org.ripple.bouncycastle.jce.interfaces.ecprivatekey;
import org.ripple.bouncycastle.jce.interfaces.ecpublickey;
import org.ripple.bouncycastle.jce.interfaces.ieskey;
import org.ripple.bouncycastle.jce.provider.bouncycastleprovider;
import org.ripple.bouncycastle.jce.spec.iesparameterspec;

public class cipherspi
    extends javax.crypto.cipherspi
{
    private iesengine cipher;
    private int                     state = -1;
    private bytearrayoutputstream   buffer = new bytearrayoutputstream();
    private algorithmparameters     engineparam = null;
    private iesparameterspec        engineparams = null;

    //
    // specs we can handle.
    //
    private class[]                 availablespecs =
                                    {
                                        iesparameterspec.class
                                    };

    public cipherspi(
        iesengine engine)
    {
        cipher = engine;
    }

    protected int enginegetblocksize() 
    {
        return 0;
    }

    protected byte[] enginegetiv() 
    {
        return null;
    }

    protected int enginegetkeysize(
        key     key) 
    {
        if (!(key instanceof ieskey))
        {
            throw new illegalargumentexception("must be passed ie key");
        }

        ieskey   iekey = (ieskey)key;

        if (iekey.getprivate() instanceof dhprivatekey)
        {
            dhprivatekey   k = (dhprivatekey)iekey.getprivate();

            return k.getx().bitlength();
        }
        else if (iekey.getprivate() instanceof ecprivatekey)
        {
            ecprivatekey   k = (ecprivatekey)iekey.getprivate();

            return k.getd().bitlength();
        }

        throw new illegalargumentexception("not an ie key!");
    }

    protected int enginegetoutputsize(
        int     inputlen) 
    {
        if (state == cipher.encrypt_mode || state == cipher.wrap_mode)
        {
            return buffer.size() + inputlen + 20; /* sha1 mac size */
        }
        else if (state == cipher.decrypt_mode || state == cipher.unwrap_mode)
        {
            return buffer.size() + inputlen - 20;
        }
        else
        {
            throw new illegalstateexception("cipher not initialised");
        }
    }

    protected algorithmparameters enginegetparameters() 
    {
        if (engineparam == null)
        {
            if (engineparams != null)
            {
                string  name = "ies";

                try
                {
                    engineparam = algorithmparameters.getinstance(name, bouncycastleprovider.provider_name);
                    engineparam.init(engineparams);
                }
                catch (exception e)
                {
                    throw new runtimeexception(e.tostring());
                }
            }
        }

        return engineparam;
    }

    protected void enginesetmode(
        string  mode) 
    {
        throw new illegalargumentexception("can't support mode " + mode);
    }

    protected void enginesetpadding(
        string  padding) 
        throws nosuchpaddingexception
    {
        throw new nosuchpaddingexception(padding + " unavailable with rsa.");
    }

    protected void engineinit(
        int                     opmode,
        key                     key,
        algorithmparameterspec  params,
        securerandom            random) 
    throws invalidkeyexception, invalidalgorithmparameterexception
    {
        if (!(key instanceof ieskey))
        {
            throw new invalidkeyexception("must be passed ies key");
        }

        if (params == null && (opmode == cipher.encrypt_mode || opmode == cipher.wrap_mode))
        {
            //
            // if nothing is specified we set up for a 128 bit mac, with
            // 128 bit derivation vectors.
            //
            byte[]  d = new byte[16];
            byte[]  e = new byte[16];

            if (random == null)
            {
                random = new securerandom();
            }

            random.nextbytes(d);
            random.nextbytes(e);

            params = new iesparameterspec(d, e, 128);
        }
        else if (!(params instanceof iesparameterspec))
        {
            throw new invalidalgorithmparameterexception("must be passed ies parameters");
        }

        ieskey       iekey = (ieskey)key;

        cipherparameters pubkey;
        cipherparameters privkey;

        if (iekey.getpublic() instanceof ecpublickey)
        {
            pubkey = ecutil.generatepublickeyparameter(iekey.getpublic());
            privkey = ecutil.generateprivatekeyparameter(iekey.getprivate());
        }
        else
        {
            pubkey = dhutil.generatepublickeyparameter(iekey.getpublic());
            privkey = dhutil.generateprivatekeyparameter(iekey.getprivate());
        }

        this.engineparams = (iesparameterspec)params;

        iesparameters       p = new iesparameters(engineparams.getderivationv(), engineparams.getencodingv(), engineparams.getmackeysize());

        this.state = opmode;

        buffer.reset();

        switch (opmode)
        {
        case cipher.encrypt_mode:
        case cipher.wrap_mode:
            cipher.init(true, privkey, pubkey, p);
            break;
        case cipher.decrypt_mode:
        case cipher.unwrap_mode:
            cipher.init(false, privkey, pubkey, p);
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

        engineparam = params;
        engineinit(opmode, key, paramspec, random);
    }

    protected void engineinit(
        int                 opmode,
        key                 key,
        securerandom        random) 
    throws invalidkeyexception
    {
        if (opmode == cipher.encrypt_mode || opmode == cipher.wrap_mode)
        {
            try
            {
                engineinit(opmode, key, (algorithmparameterspec)null, random);
                return;
            }
            catch (invalidalgorithmparameterexception e)
            {
                // fall through...
            }
        }

        throw new illegalargumentexception("can't handle null parameter spec in ies");
    }

    protected byte[] engineupdate(
        byte[]  input,
        int     inputoffset,
        int     inputlen) 
    {
        buffer.write(input, inputoffset, inputlen);
        return null;
    }

    protected int engineupdate(
        byte[]  input,
        int     inputoffset,
        int     inputlen,
        byte[]  output,
        int     outputoffset) 
    {
        buffer.write(input, inputoffset, inputlen);
        return 0;
    }

    protected byte[] enginedofinal(
        byte[]  input,
        int     inputoffset,
        int     inputlen) 
        throws illegalblocksizeexception, badpaddingexception
    {
        if (inputlen != 0)
        {
            buffer.write(input, inputoffset, inputlen);
        }

        try
        {
            byte[]  buf = buffer.tobytearray();

            buffer.reset();

            return cipher.processblock(buf, 0, buf.length);
        }
        catch (invalidciphertextexception e)
        {
            throw new badpaddingexception(e.getmessage());
        }
    }

    protected int enginedofinal(
        byte[]  input,
        int     inputoffset,
        int     inputlen,
        byte[]  output,
        int     outputoffset) 
        throws illegalblocksizeexception, badpaddingexception
    {
        if (inputlen != 0)
        {
            buffer.write(input, inputoffset, inputlen);
        }

        try
        {
            byte[]  buf = buffer.tobytearray();

            buffer.reset();

            buf = cipher.processblock(buf, 0, buf.length);

            system.arraycopy(buf, 0, output, outputoffset, buf.length);

            return buf.length;
        }
        catch (invalidciphertextexception e)
        {
            throw new badpaddingexception(e.getmessage());
        }
    }

    static public class ies
        extends cipherspi
    {
        public ies()
        {
            super(new iesengine(
                   new dhbasicagreement(),
                   new kdf2bytesgenerator(new sha1digest()),
                   new hmac(new sha1digest())));
        }
    }
}
