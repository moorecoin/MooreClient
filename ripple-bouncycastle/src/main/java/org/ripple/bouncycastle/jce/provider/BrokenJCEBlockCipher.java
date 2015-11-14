package org.ripple.bouncycastle.jce.provider;

import java.security.algorithmparameters;
import java.security.invalidalgorithmparameterexception;
import java.security.invalidkeyexception;
import java.security.key;
import java.security.keyfactory;
import java.security.nosuchalgorithmexception;
import java.security.nosuchproviderexception;
import java.security.securerandom;
import java.security.spec.algorithmparameterspec;
import java.security.spec.invalidkeyspecexception;
import java.security.spec.pkcs8encodedkeyspec;
import java.security.spec.x509encodedkeyspec;

import javax.crypto.badpaddingexception;
import javax.crypto.cipher;
import javax.crypto.illegalblocksizeexception;
import javax.crypto.nosuchpaddingexception;
import javax.crypto.spec.ivparameterspec;
import javax.crypto.spec.pbeparameterspec;
import javax.crypto.spec.rc2parameterspec;
import javax.crypto.spec.rc5parameterspec;
import javax.crypto.spec.secretkeyspec;

import org.ripple.bouncycastle.crypto.blockcipher;
import org.ripple.bouncycastle.crypto.bufferedblockcipher;
import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.datalengthexception;
import org.ripple.bouncycastle.crypto.invalidciphertextexception;
import org.ripple.bouncycastle.crypto.engines.desengine;
import org.ripple.bouncycastle.crypto.engines.desedeengine;
import org.ripple.bouncycastle.crypto.engines.twofishengine;
import org.ripple.bouncycastle.crypto.modes.cbcblockcipher;
import org.ripple.bouncycastle.crypto.modes.cfbblockcipher;
import org.ripple.bouncycastle.crypto.modes.ctsblockcipher;
import org.ripple.bouncycastle.crypto.modes.ofbblockcipher;
import org.ripple.bouncycastle.crypto.paddings.paddedbufferedblockcipher;
import org.ripple.bouncycastle.crypto.params.keyparameter;
import org.ripple.bouncycastle.crypto.params.parameterswithiv;
import org.ripple.bouncycastle.crypto.params.rc2parameters;
import org.ripple.bouncycastle.crypto.params.rc5parameters;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.bcpbekey;
import org.ripple.bouncycastle.util.strings;

public class brokenjceblockcipher
    implements brokenpbe
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
 
    private bufferedblockcipher     cipher;
    private parameterswithiv        ivparam;

    private int                     pbetype = pkcs12;
    private int                     pbehash = sha1;
    private int                     pbekeysize;
    private int                     pbeivsize;

    private int                     ivlength = 0;

    private algorithmparameters     engineparams = null;

    protected brokenjceblockcipher(
        blockcipher engine)
    {
        cipher = new paddedbufferedblockcipher(engine);
    }
        
    protected brokenjceblockcipher(
        blockcipher engine,
        int         pbetype,
        int         pbehash,
        int         pbekeysize,
        int         pbeivsize)
    {
        cipher = new paddedbufferedblockcipher(engine);

        this.pbetype = pbetype;
        this.pbehash = pbehash;
        this.pbekeysize = pbekeysize;
        this.pbeivsize = pbeivsize;
    }

    protected int enginegetblocksize() 
    {
        return cipher.getblocksize();
    }

    protected byte[] enginegetiv() 
    {
        return (ivparam != null) ? ivparam.getiv() : null;
    }

    protected int enginegetkeysize(
        key     key) 
    {
        return key.getencoded().length;
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
            if (ivparam != null)
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
    {
        string  modename = strings.touppercase(mode);

        if (modename.equals("ecb"))
        {
            ivlength = 0;
            cipher = new paddedbufferedblockcipher(cipher.getunderlyingcipher());
        }
        else if (modename.equals("cbc"))
        {
            ivlength = cipher.getunderlyingcipher().getblocksize();
            cipher = new paddedbufferedblockcipher(
                            new cbcblockcipher(cipher.getunderlyingcipher()));
        }
        else if (modename.startswith("ofb"))
        {
            ivlength = cipher.getunderlyingcipher().getblocksize();
            if (modename.length() != 3)
            {
                int wordsize = integer.parseint(modename.substring(3));

                cipher = new paddedbufferedblockcipher(
                                new ofbblockcipher(cipher.getunderlyingcipher(), wordsize));
            }
            else
            {
                cipher = new paddedbufferedblockcipher(
                        new ofbblockcipher(cipher.getunderlyingcipher(), 8 * cipher.getblocksize()));
            }
        }
        else if (modename.startswith("cfb"))
        {
            ivlength = cipher.getunderlyingcipher().getblocksize();
            if (modename.length() != 3)
            {
                int wordsize = integer.parseint(modename.substring(3));

                cipher = new paddedbufferedblockcipher(
                                new cfbblockcipher(cipher.getunderlyingcipher(), wordsize));
            }
            else
            {
                cipher = new paddedbufferedblockcipher(
                        new cfbblockcipher(cipher.getunderlyingcipher(), 8 * cipher.getblocksize()));
            }
        }
        else
        {
            throw new illegalargumentexception("can't support mode " + mode);
        }
    }

    protected void enginesetpadding(
        string  padding) 
    throws nosuchpaddingexception
    {
        string  paddingname = strings.touppercase(padding);

        if (paddingname.equals("nopadding"))
        {
            cipher = new bufferedblockcipher(cipher.getunderlyingcipher());
        }
        else if (paddingname.equals("pkcs5padding") || paddingname.equals("pkcs7padding") || paddingname.equals("iso10126padding"))
        {
            cipher = new paddedbufferedblockcipher(cipher.getunderlyingcipher());
        }
        else if (paddingname.equals("withcts"))
        {
            cipher = new ctsblockcipher(cipher.getunderlyingcipher());
        }
        else
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

        //
        // a note on iv's - if ivlength is zero the iv gets ignored (we don't use it).
        //
        if (key instanceof bcpbekey)
        {
            param = brokenpbe.util.makepbeparameters((bcpbekey)key, params, pbetype, pbehash,
                        cipher.getunderlyingcipher().getalgorithmname(), pbekeysize, pbeivsize);

            if (pbeivsize != 0)
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
                param = new parameterswithiv(new keyparameter(key.getencoded()), ((ivparameterspec)params).getiv());
                ivparam = (parameterswithiv)param;
            }
            else
            {
                param = new keyparameter(key.getencoded());
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
            if (rc5param.getwordsize() != 32)
            {
                throw new illegalargumentexception("can only accept rc5 word size 32 (at the moment...)");
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
            if (random == null)
            {
                random = new securerandom();
            }

            if ((opmode == cipher.encrypt_mode) || (opmode == cipher.wrap_mode))
            {
                byte[]  iv = new byte[ivlength];

                random.nextbytes(iv);
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
        int     length = cipher.getupdateoutputsize(inputlen);

        if (length > 0)
        {
                byte[]  out = new byte[length];

                cipher.processbytes(input, inputoffset, inputlen, out, 0);
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
    {
        return cipher.processbytes(input, inputoffset, inputlen, output, outputoffset);
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
        throws illegalblocksizeexception, badpaddingexception
    {
        int     len = 0;

        if (inputlen != 0)
        {
                len = cipher.processbytes(input, inputoffset, inputlen, output, outputoffset);
        }

        try
        {
            return len + cipher.dofinal(output, outputoffset + len);
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

    protected byte[] enginewrap(
        key     key) 
    throws illegalblocksizeexception, java.security.invalidkeyexception
    {
        byte[] encoded = key.getencoded();
        if (encoded == null)
        {
            throw new invalidkeyexception("cannot wrap key, null encoding.");
        }

        try
        {
            return enginedofinal(encoded, 0, encoded.length);
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
    throws invalidkeyexception
    {
        byte[] encoded = null;
        try
        {
            encoded = enginedofinal(wrappedkey, 0, wrappedkey.length);
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
            catch (nosuchalgorithmexception e)
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

    /*
     * the ciphers that inherit from us.
     */

    /**
     * pbewithmd5anddes
     */
    static public class brokepbewithmd5anddes
        extends brokenjceblockcipher
    {
        public brokepbewithmd5anddes()
        {
            super(new cbcblockcipher(new desengine()), pkcs5s1, md5, 64, 64);
        }
    }

    /**
     * pbewithsha1anddes
     */
    static public class brokepbewithsha1anddes
        extends brokenjceblockcipher
    {
        public brokepbewithsha1anddes()
        {
            super(new cbcblockcipher(new desengine()), pkcs5s1, sha1, 64, 64);
        }
    }

    /**
     * pbewithshaand3-keytripledes-cbc
     */
    static public class brokepbewithshaanddes3key
        extends brokenjceblockcipher
    {
        public brokepbewithshaanddes3key()
        {
            super(new cbcblockcipher(new desedeengine()), pkcs12, sha1, 192, 64);
        }
    }

    /**
     * oldpbewithshaand3-keytripledes-cbc
     */
    static public class oldpbewithshaanddes3key
        extends brokenjceblockcipher
    {
        public oldpbewithshaanddes3key()
        {
            super(new cbcblockcipher(new desedeengine()), old_pkcs12, sha1, 192, 64);
        }
    }

    /**
     * pbewithshaand2-keytripledes-cbc
     */
    static public class brokepbewithshaanddes2key
        extends brokenjceblockcipher
    {
        public brokepbewithshaanddes2key()
        {
            super(new cbcblockcipher(new desedeengine()), pkcs12, sha1, 128, 64);
        }
    }

    /**
     * oldpbewithshaandtwofish-cbc
     */
    static public class oldpbewithshaandtwofish
        extends brokenjceblockcipher
    {
        public oldpbewithshaandtwofish()
        {
            super(new cbcblockcipher(new twofishengine()), old_pkcs12, sha1, 256, 128);
        }
    }
}
