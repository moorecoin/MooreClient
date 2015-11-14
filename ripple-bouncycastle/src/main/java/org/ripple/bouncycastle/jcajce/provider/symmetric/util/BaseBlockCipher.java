package org.ripple.bouncycastle.jcajce.provider.symmetric.util;

import java.security.algorithmparameters;
import java.security.invalidalgorithmparameterexception;
import java.security.invalidkeyexception;
import java.security.invalidparameterexception;
import java.security.key;
import java.security.nosuchalgorithmexception;
import java.security.securerandom;
import java.security.spec.algorithmparameterspec;

import javax.crypto.badpaddingexception;
import javax.crypto.cipher;
import javax.crypto.illegalblocksizeexception;
import javax.crypto.nosuchpaddingexception;
import javax.crypto.secretkey;
import javax.crypto.shortbufferexception;
import javax.crypto.spec.ivparameterspec;
import javax.crypto.spec.pbeparameterspec;
import javax.crypto.spec.rc2parameterspec;
import javax.crypto.spec.rc5parameterspec;

import org.ripple.bouncycastle.crypto.blockcipher;
import org.ripple.bouncycastle.crypto.bufferedblockcipher;
import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.datalengthexception;
import org.ripple.bouncycastle.crypto.invalidciphertextexception;
import org.ripple.bouncycastle.crypto.outputlengthexception;
import org.ripple.bouncycastle.crypto.modes.aeadblockcipher;
import org.ripple.bouncycastle.crypto.modes.cbcblockcipher;
import org.ripple.bouncycastle.crypto.modes.ccmblockcipher;
import org.ripple.bouncycastle.crypto.modes.cfbblockcipher;
import org.ripple.bouncycastle.crypto.modes.ctsblockcipher;
import org.ripple.bouncycastle.crypto.modes.eaxblockcipher;
import org.ripple.bouncycastle.crypto.modes.gcmblockcipher;
import org.ripple.bouncycastle.crypto.modes.gofbblockcipher;
import org.ripple.bouncycastle.crypto.modes.ocbblockcipher;
import org.ripple.bouncycastle.crypto.modes.ofbblockcipher;
import org.ripple.bouncycastle.crypto.modes.openpgpcfbblockcipher;
import org.ripple.bouncycastle.crypto.modes.pgpcfbblockcipher;
import org.ripple.bouncycastle.crypto.modes.sicblockcipher;
import org.ripple.bouncycastle.crypto.paddings.blockcipherpadding;
import org.ripple.bouncycastle.crypto.paddings.iso10126d2padding;
import org.ripple.bouncycastle.crypto.paddings.iso7816d4padding;
import org.ripple.bouncycastle.crypto.paddings.paddedbufferedblockcipher;
import org.ripple.bouncycastle.crypto.paddings.tbcpadding;
import org.ripple.bouncycastle.crypto.paddings.x923padding;
import org.ripple.bouncycastle.crypto.paddings.zerobytepadding;
import org.ripple.bouncycastle.crypto.params.keyparameter;
import org.ripple.bouncycastle.crypto.params.parameterswithiv;
import org.ripple.bouncycastle.crypto.params.parameterswithrandom;
import org.ripple.bouncycastle.crypto.params.parameterswithsbox;
import org.ripple.bouncycastle.crypto.params.rc2parameters;
import org.ripple.bouncycastle.crypto.params.rc5parameters;
import org.ripple.bouncycastle.jce.provider.bouncycastleprovider;
import org.ripple.bouncycastle.jce.spec.gost28147parameterspec;
import org.ripple.bouncycastle.jce.spec.repeatedsecretkeyspec;
import org.ripple.bouncycastle.util.strings;

public class baseblockcipher
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
                                        pbeparameterspec.class,
                                        gost28147parameterspec.class
                                    };

    private blockcipher             baseengine;
    private blockcipherprovider     engineprovider;
    private genericblockcipher      cipher;
    private parameterswithiv        ivparam;

    private int                     ivlength = 0;

    private boolean                 padded;

    private pbeparameterspec        pbespec = null;
    private string                  pbealgorithm = null;

    private string                  modename = null;

    protected baseblockcipher(
        blockcipher engine)
    {
        baseengine = engine;

        cipher = new bufferedgenericblockcipher(engine);
    }

    protected baseblockcipher(
        blockcipherprovider provider)
    {
        baseengine = provider.get();
        engineprovider = provider;

        cipher = new bufferedgenericblockcipher(provider.get());
    }

    protected baseblockcipher(
        org.ripple.bouncycastle.crypto.blockcipher engine,
        int ivlength)
    {
        baseengine = engine;

        this.cipher = new bufferedgenericblockcipher(engine);
        this.ivlength = ivlength / 8;
    }

    protected baseblockcipher(
        bufferedblockcipher engine,
        int ivlength)
    {
        baseengine = engine.getunderlyingcipher();

        this.cipher = new bufferedgenericblockcipher(engine);
        this.ivlength = ivlength / 8;
    }

    protected int enginegetblocksize()
    {
        return baseengine.getblocksize();
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
        return cipher.getoutputsize(inputlen);
    }

    protected algorithmparameters enginegetparameters()
    {
        if (engineparams == null)
        {
            if (pbespec != null)
            {
                try
                {
                    engineparams = algorithmparameters.getinstance(pbealgorithm, bouncycastleprovider.provider_name);
                    engineparams.init(pbespec);
                }
                catch (exception e)
                {
                    return null;
                }
            }
            else if (ivparam != null)
            {
                string  name = cipher.getunderlyingcipher().getalgorithmname();

                if (name.indexof('/') >= 0)
                {
                    name = name.substring(0, name.indexof('/'));
                }

                try
                {
                    engineparams = algorithmparameters.getinstance(name, bouncycastleprovider.provider_name);
                    engineparams.init(ivparam.getiv());
                }
                catch (exception e)
                {
                    throw new runtimeexception(e.tostring());
                }
            }
        }

        return engineparams;
    }

    protected void enginesetmode(
        string  mode)
        throws nosuchalgorithmexception
    {
        modename = strings.touppercase(mode);

        if (modename.equals("ecb"))
        {
            ivlength = 0;
            cipher = new bufferedgenericblockcipher(baseengine);
        }
        else if (modename.equals("cbc"))
        {
            ivlength = baseengine.getblocksize();
            cipher = new bufferedgenericblockcipher(
                            new cbcblockcipher(baseengine));
        }
        else if (modename.startswith("ofb"))
        {
            ivlength = baseengine.getblocksize();
            if (modename.length() != 3)
            {
                int wordsize = integer.parseint(modename.substring(3));

                cipher = new bufferedgenericblockcipher(
                                new ofbblockcipher(baseengine, wordsize));
            }
            else
            {
                cipher = new bufferedgenericblockcipher(
                        new ofbblockcipher(baseengine, 8 * baseengine.getblocksize()));
            }
        }
        else if (modename.startswith("cfb"))
        {
            ivlength = baseengine.getblocksize();
            if (modename.length() != 3)
            {
                int wordsize = integer.parseint(modename.substring(3));

                cipher = new bufferedgenericblockcipher(
                                new cfbblockcipher(baseengine, wordsize));
            }
            else
            {
                cipher = new bufferedgenericblockcipher(
                        new cfbblockcipher(baseengine, 8 * baseengine.getblocksize()));
            }
        }
        else if (modename.startswith("pgp"))
        {
            boolean inlineiv = modename.equalsignorecase("pgpcfbwithiv");

            ivlength = baseengine.getblocksize();
            cipher = new bufferedgenericblockcipher(
                new pgpcfbblockcipher(baseengine, inlineiv));
        }
        else if (modename.equalsignorecase("openpgpcfb"))
        {
            ivlength = 0;
            cipher = new bufferedgenericblockcipher(
                new openpgpcfbblockcipher(baseengine));
        }
        else if (modename.startswith("sic"))
        {
            ivlength = baseengine.getblocksize();
            if (ivlength < 16)
            {
                throw new illegalargumentexception("warning: sic-mode can become a twotime-pad if the blocksize of the cipher is too small. use a cipher with a block size of at least 128 bits (e.g. aes)");
            }
            cipher = new bufferedgenericblockcipher(new bufferedblockcipher(
                        new sicblockcipher(baseengine)));
        }
        else if (modename.startswith("ctr"))
        {
            ivlength = baseengine.getblocksize();
            cipher = new bufferedgenericblockcipher(new bufferedblockcipher(
                        new sicblockcipher(baseengine)));
        }
        else if (modename.startswith("gofb"))
        {
            ivlength = baseengine.getblocksize();
            cipher = new bufferedgenericblockcipher(new bufferedblockcipher(
                        new gofbblockcipher(baseengine)));
        }
        else if (modename.startswith("cts"))
        {
            ivlength = baseengine.getblocksize();
            cipher = new bufferedgenericblockcipher(new ctsblockcipher(new cbcblockcipher(baseengine)));
        }
        else if (modename.startswith("ccm"))
        {
            ivlength = baseengine.getblocksize();
            cipher = new aeadgenericblockcipher(new ccmblockcipher(baseengine));
        }
        else if (modename.startswith("ocb"))
        {
            if (engineprovider != null)
            {
                ivlength = baseengine.getblocksize();
                cipher = new aeadgenericblockcipher(new ocbblockcipher(baseengine, engineprovider.get()));
            }
            else
            {
                throw new nosuchalgorithmexception("can't support mode " + mode);
            }
        }
        else if (modename.startswith("eax"))
        {
            ivlength = baseengine.getblocksize();
            cipher = new aeadgenericblockcipher(new eaxblockcipher(baseengine));
        }
        else if (modename.startswith("gcm"))
        {
            ivlength = baseengine.getblocksize();
            cipher = new aeadgenericblockcipher(new gcmblockcipher(baseengine));
        }
        else
        {
            throw new nosuchalgorithmexception("can't support mode " + mode);
        }
    }

    protected void enginesetpadding(
        string  padding)
    throws nosuchpaddingexception
    {
        string  paddingname = strings.touppercase(padding);

        if (paddingname.equals("nopadding"))
        {
            if (cipher.wraponnopadding())
            {
                cipher = new bufferedgenericblockcipher(new bufferedblockcipher(cipher.getunderlyingcipher()));
            }
        }
        else if (paddingname.equals("withcts"))
        {
            cipher = new bufferedgenericblockcipher(new ctsblockcipher(cipher.getunderlyingcipher()));
        }
        else
        {
            padded = true;

            if (isaeadmodename(modename))
            {
                throw new nosuchpaddingexception("only nopadding can be used with aead modes.");
            }
            else if (paddingname.equals("pkcs5padding") || paddingname.equals("pkcs7padding"))
            {
                cipher = new bufferedgenericblockcipher(cipher.getunderlyingcipher());
            }
            else if (paddingname.equals("zerobytepadding"))
            {
                cipher = new bufferedgenericblockcipher(cipher.getunderlyingcipher(), new zerobytepadding());
            }
            else if (paddingname.equals("iso10126padding") || paddingname.equals("iso10126-2padding"))
            {
                cipher = new bufferedgenericblockcipher(cipher.getunderlyingcipher(), new iso10126d2padding());
            }
            else if (paddingname.equals("x9.23padding") || paddingname.equals("x923padding"))
            {
                cipher = new bufferedgenericblockcipher(cipher.getunderlyingcipher(), new x923padding());
            }
            else if (paddingname.equals("iso7816-4padding") || paddingname.equals("iso9797-1padding"))
            {
                cipher = new bufferedgenericblockcipher(cipher.getunderlyingcipher(), new iso7816d4padding());
            }
            else if (paddingname.equals("tbcpadding"))
            {
                cipher = new bufferedgenericblockcipher(cipher.getunderlyingcipher(), new tbcpadding());
            }
            else
            {
                throw new nosuchpaddingexception("padding " + padding + " unknown.");
            }
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

        //
        // for rc5-64 we must have some default parameters
        //
        if (params == null && baseengine.getalgorithmname().startswith("rc5-64"))
        {
            throw new invalidalgorithmparameterexception("rc5 requires an rc5parametersspec to be passed in.");
        }

        //
        // a note on iv's - if ivlength is zero the iv gets ignored (we don't use it).
        //
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
                if (params instanceof ivparameterspec)
                {
                    ivparameterspec iv = (ivparameterspec)params;

                    param = new parameterswithiv(param, iv.getiv());
                }
            }
            else if (params instanceof pbeparameterspec)
            {
                pbespec = (pbeparameterspec)params;
                param = pbe.util.makepbeparameters(k, params, cipher.getunderlyingcipher().getalgorithmname());
            }
            else
            {
                throw new invalidalgorithmparameterexception("pbe requires pbe parameters to be set.");
            }

            if (param instanceof parameterswithiv)
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
            if (ivlength != 0)
            {
                ivparameterspec p = (ivparameterspec)params;

                if (p.getiv().length != ivlength && !isaeadmodename(modename))
                {
                    throw new invalidalgorithmparameterexception("iv must be " + ivlength + " bytes long.");
                }

                if (key instanceof repeatedsecretkeyspec)
                {
                    param = new parameterswithiv(null, p.getiv());
                    ivparam = (parameterswithiv)param;
                }
                else
                {
                    param = new parameterswithiv(new keyparameter(key.getencoded()), p.getiv());
                    ivparam = (parameterswithiv)param;
                }
            }
            else
            {
                if (modename != null && modename.equals("ecb"))
                {
                    throw new invalidalgorithmparameterexception("ecb mode does not use an iv");
                }
                
                param = new keyparameter(key.getencoded());
            }
        }
        else if (params instanceof gost28147parameterspec)
        {
            gost28147parameterspec    gost28147param = (gost28147parameterspec)params;

            param = new parameterswithsbox(
                       new keyparameter(key.getencoded()), ((gost28147parameterspec)params).getsbox());

            if (gost28147param.getiv() != null && ivlength != 0)
            {
                param = new parameterswithiv(param, gost28147param.getiv());
                ivparam = (parameterswithiv)param;
            }
        }
        else if (params instanceof rc2parameterspec)
        {
            rc2parameterspec    rc2param = (rc2parameterspec)params;

            param = new rc2parameters(key.getencoded(), ((rc2parameterspec)params).geteffectivekeybits());

            if (rc2param.getiv() != null && ivlength != 0)
            {
                param = new parameterswithiv(param, rc2param.getiv());
                ivparam = (parameterswithiv)param;
            }
        }
        else if (params instanceof rc5parameterspec)
        {
            rc5parameterspec    rc5param = (rc5parameterspec)params;

            param = new rc5parameters(key.getencoded(), ((rc5parameterspec)params).getrounds());
            if (baseengine.getalgorithmname().startswith("rc5"))
            {
                if (baseengine.getalgorithmname().equals("rc5-32"))
                {
                    if (rc5param.getwordsize() != 32)
                    {
                        throw new invalidalgorithmparameterexception("rc5 already set up for a word size of 32 not " + rc5param.getwordsize() + ".");
                    }
                }
                else if (baseengine.getalgorithmname().equals("rc5-64"))
                {
                    if (rc5param.getwordsize() != 64)
                    {
                        throw new invalidalgorithmparameterexception("rc5 already set up for a word size of 64 not " + rc5param.getwordsize() + ".");
                    }
                }
            }
            else
            {
                throw new invalidalgorithmparameterexception("rc5 parameters passed to a cipher that is not rc5.");
            }
            if ((rc5param.getiv() != null) && (ivlength != 0))
            {
                param = new parameterswithiv(param, rc5param.getiv());
                ivparam = (parameterswithiv)param;
            }
        }
        else
        {
            throw new invalidalgorithmparameterexception("unknown parameter type.");
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
            else if (cipher.getunderlyingcipher().getalgorithmname().indexof("pgpcfb") < 0)
            {
                throw new invalidalgorithmparameterexception("no iv set when one expected");
            }
        }

        if (random != null && padded)
        {
            param = new parameterswithrandom(param, random);
        }

        try
        {
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
                throw new invalidparameterexception("unknown opmode " + opmode + " passed");
            }
        }
        catch (exception e)
        {
            throw new invalidkeyexception(e.getmessage());
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
                    // try again if possible
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
        int     length = cipher.getupdateoutputsize(inputlen);

        if (length > 0)
        {
                byte[]  out = new byte[length];

                int len = cipher.processbytes(input, inputoffset, inputlen, out, 0);

                if (len == 0)
                {
                    return null;
                }
                else if (len != out.length)
                {
                    byte[]  tmp = new byte[len];

                    system.arraycopy(out, 0, tmp, 0, len);

                    return tmp;
                }

                return out;
        }

        cipher.processbytes(input, inputoffset, inputlen, null, 0);

        return null;
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
            return cipher.processbytes(input, inputoffset, inputlen, output, outputoffset);
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
        throws illegalblocksizeexception, badpaddingexception
    {
        int     len = 0;
        byte[]  tmp = new byte[enginegetoutputsize(inputlen)];

        if (inputlen != 0)
        {
            len = cipher.processbytes(input, inputoffset, inputlen, tmp, 0);
        }

        try
        {
            len += cipher.dofinal(tmp, len);
        }
        catch (datalengthexception e)
        {
            throw new illegalblocksizeexception(e.getmessage());
        }
        catch (invalidciphertextexception e)
        {
            throw new badpaddingexception(e.getmessage());
        }

        if (len == tmp.length)
        {
            return tmp;
        }

        byte[]  out = new byte[len];

        system.arraycopy(tmp, 0, out, 0, len);

        return out;
    }

    protected int enginedofinal(
        byte[]  input,
        int     inputoffset,
        int     inputlen,
        byte[]  output,
        int     outputoffset)
        throws illegalblocksizeexception, badpaddingexception, shortbufferexception
    {
        try
        {
            int     len = 0;

            if (inputlen != 0)
            {
                len = cipher.processbytes(input, inputoffset, inputlen, output, outputoffset);
            }

            return (len + cipher.dofinal(output, outputoffset + len));
        }
        catch (outputlengthexception e)
        {
            throw new shortbufferexception(e.getmessage());
        }
        catch (datalengthexception e)
        {
            throw new illegalblocksizeexception(e.getmessage());
        }
        catch (invalidciphertextexception e)
        {
            throw new badpaddingexception(e.getmessage());
        }
    }

    private boolean isaeadmodename(
        string modename)
    {
        return "ccm".equals(modename) || "eax".equals(modename) || "gcm".equals(modename) || "ocb".equals(modename);
    }

    /*
     * the ciphers that inherit from us.
     */

    static private interface genericblockcipher
    {
        public void init(boolean forencryption, cipherparameters params)
            throws illegalargumentexception;

        public boolean wraponnopadding();

        public string getalgorithmname();

        public org.ripple.bouncycastle.crypto.blockcipher getunderlyingcipher();

        public int getoutputsize(int len);

        public int getupdateoutputsize(int len);

        public int processbyte(byte in, byte[] out, int outoff)
            throws datalengthexception;

        public int processbytes(byte[] in, int inoff, int len, byte[] out, int outoff)
            throws datalengthexception;

        public int dofinal(byte[] out, int outoff)
            throws illegalstateexception, invalidciphertextexception;
    }

    private static class bufferedgenericblockcipher
        implements genericblockcipher
    {
        private bufferedblockcipher cipher;

        bufferedgenericblockcipher(bufferedblockcipher cipher)
        {
            this.cipher = cipher;
        }

        bufferedgenericblockcipher(org.ripple.bouncycastle.crypto.blockcipher cipher)
        {
            this.cipher = new paddedbufferedblockcipher(cipher);
        }

        bufferedgenericblockcipher(org.ripple.bouncycastle.crypto.blockcipher cipher, blockcipherpadding padding)
        {
            this.cipher = new paddedbufferedblockcipher(cipher, padding);
        }

        public void init(boolean forencryption, cipherparameters params)
            throws illegalargumentexception
        {
            cipher.init(forencryption, params);
        }

        public boolean wraponnopadding()
        {
            return !(cipher instanceof ctsblockcipher);
        }

        public string getalgorithmname()
        {
            return cipher.getunderlyingcipher().getalgorithmname();
        }

        public org.ripple.bouncycastle.crypto.blockcipher getunderlyingcipher()
        {
            return cipher.getunderlyingcipher();
        }

        public int getoutputsize(int len)
        {
            return cipher.getoutputsize(len);
        }

        public int getupdateoutputsize(int len)
        {
            return cipher.getupdateoutputsize(len);
        }

        public int processbyte(byte in, byte[] out, int outoff) throws datalengthexception
        {
            return cipher.processbyte(in, out, outoff);
        }

        public int processbytes(byte[] in, int inoff, int len, byte[] out, int outoff) throws datalengthexception
        {
            return cipher.processbytes(in, inoff, len, out, outoff);
        }

        public int dofinal(byte[] out, int outoff) throws illegalstateexception, invalidciphertextexception
        {
            return cipher.dofinal(out, outoff);
        }
    }

    private static class aeadgenericblockcipher
        implements genericblockcipher
    {
        private aeadblockcipher cipher;

        aeadgenericblockcipher(aeadblockcipher cipher)
        {
            this.cipher = cipher;
        }

        public void init(boolean forencryption, cipherparameters params)
            throws illegalargumentexception
        {
            cipher.init(forencryption, params);
        }

        public string getalgorithmname()
        {
            return cipher.getunderlyingcipher().getalgorithmname();
        }

        public boolean wraponnopadding()
        {
            return false;
        }

        public org.ripple.bouncycastle.crypto.blockcipher getunderlyingcipher()
        {
            return cipher.getunderlyingcipher();
        }

        public int getoutputsize(int len)
        {
            return cipher.getoutputsize(len);
        }

        public int getupdateoutputsize(int len)
        {
            return cipher.getupdateoutputsize(len);
        }

        public int processbyte(byte in, byte[] out, int outoff) throws datalengthexception
        {
            return cipher.processbyte(in, out, outoff);
        }

        public int processbytes(byte[] in, int inoff, int len, byte[] out, int outoff) throws datalengthexception
        {
            return cipher.processbytes(in, inoff, len, out, outoff);
        }

        public int dofinal(byte[] out, int outoff) throws illegalstateexception, invalidciphertextexception
        {
            return cipher.dofinal(out, outoff);
        }
    }
}
