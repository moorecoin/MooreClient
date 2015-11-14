package org.ripple.bouncycastle.jcajce.provider.asymmetric.elgamal;

import java.security.algorithmparameters;
import java.security.invalidalgorithmparameterexception;
import java.security.invalidkeyexception;
import java.security.invalidparameterexception;
import java.security.key;
import java.security.nosuchalgorithmexception;
import java.security.privatekey;
import java.security.publickey;
import java.security.securerandom;
import java.security.spec.algorithmparameterspec;
import java.security.spec.mgf1parameterspec;

import javax.crypto.badpaddingexception;
import javax.crypto.illegalblocksizeexception;
import javax.crypto.nosuchpaddingexception;
import javax.crypto.interfaces.dhkey;
import javax.crypto.spec.oaepparameterspec;
import javax.crypto.spec.psource;

import org.ripple.bouncycastle.crypto.asymmetricblockcipher;
import org.ripple.bouncycastle.crypto.bufferedasymmetricblockcipher;
import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.digest;
import org.ripple.bouncycastle.crypto.invalidciphertextexception;
import org.ripple.bouncycastle.crypto.encodings.iso9796d1encoding;
import org.ripple.bouncycastle.crypto.encodings.oaepencoding;
import org.ripple.bouncycastle.crypto.encodings.pkcs1encoding;
import org.ripple.bouncycastle.crypto.engines.elgamalengine;
import org.ripple.bouncycastle.crypto.params.parameterswithrandom;
import org.ripple.bouncycastle.jcajce.provider.asymmetric.util.basecipherspi;
import org.ripple.bouncycastle.jcajce.provider.util.digestfactory;
import org.ripple.bouncycastle.jce.interfaces.elgamalkey;
import org.ripple.bouncycastle.jce.interfaces.elgamalprivatekey;
import org.ripple.bouncycastle.jce.interfaces.elgamalpublickey;
import org.ripple.bouncycastle.jce.provider.bouncycastleprovider;
import org.ripple.bouncycastle.util.strings;

public class cipherspi
    extends basecipherspi
{
    private bufferedasymmetricblockcipher   cipher;
    private algorithmparameterspec          paramspec;
    private algorithmparameters             engineparams;

    public cipherspi(
        asymmetricblockcipher engine)
    {
        cipher = new bufferedasymmetricblockcipher(engine);
    }
   
    private void initfromspec(
        oaepparameterspec pspec) 
        throws nosuchpaddingexception
    {
        mgf1parameterspec   mgfparams = (mgf1parameterspec)pspec.getmgfparameters();
        digest              digest = digestfactory.getdigest(mgfparams.getdigestalgorithm());
        
        if (digest == null)
        {
            throw new nosuchpaddingexception("no match on oaep constructor for digest algorithm: "+ mgfparams.getdigestalgorithm());
        }

        cipher = new bufferedasymmetricblockcipher(new oaepencoding(new elgamalengine(), digest, ((psource.pspecified)pspec.getpsource()).getvalue()));        
        paramspec = pspec;
    }
    
    protected int enginegetblocksize() 
    {
        return cipher.getinputblocksize();
    }

    protected int enginegetkeysize(
        key     key) 
    {
        if (key instanceof elgamalkey)
        {
            elgamalkey   k = (elgamalkey)key;

            return k.getparameters().getp().bitlength();
        }
        else if (key instanceof dhkey)
        {
            dhkey   k = (dhkey)key;

            return k.getparams().getp().bitlength();
        }

        throw new illegalargumentexception("not an elgamal key!");
    }

    protected int enginegetoutputsize(
        int     inputlen) 
    {
        return cipher.getoutputblocksize();
    }

    protected algorithmparameters enginegetparameters() 
    {
        if (engineparams == null)
        {
            if (paramspec != null)
            {
                try
                {
                    engineparams = algorithmparameters.getinstance("oaep", bouncycastleprovider.provider_name);
                    engineparams.init(paramspec);
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
        string md = strings.touppercase(mode);
        
        if (md.equals("none") || md.equals("ecb"))
        {
            return;
        }
        
        throw new nosuchalgorithmexception("can't support mode " + mode);
    }

    protected void enginesetpadding(
        string  padding) 
        throws nosuchpaddingexception
    {
        string pad = strings.touppercase(padding);

        if (pad.equals("nopadding"))
        {
            cipher = new bufferedasymmetricblockcipher(new elgamalengine());
        }
        else if (pad.equals("pkcs1padding"))
        {
            cipher = new bufferedasymmetricblockcipher(new pkcs1encoding(new elgamalengine()));
        }
        else if (pad.equals("iso9796-1padding"))
        {
            cipher = new bufferedasymmetricblockcipher(new iso9796d1encoding(new elgamalengine()));
        }
        else if (pad.equals("oaeppadding"))
        {
            initfromspec(oaepparameterspec.default);
        }
        else if (pad.equals("oaepwithmd5andmgf1padding"))
        {
            initfromspec(new oaepparameterspec("md5", "mgf1", new mgf1parameterspec("md5"), psource.pspecified.default));
        }
        else if (pad.equals("oaepwithsha1andmgf1padding"))
        {
            initfromspec(oaepparameterspec.default);
        }
        else if (pad.equals("oaepwithsha224andmgf1padding"))
        {
            initfromspec(new oaepparameterspec("sha-224", "mgf1", new mgf1parameterspec("sha-224"), psource.pspecified.default));
        }
        else if (pad.equals("oaepwithsha256andmgf1padding"))
        {
            initfromspec(new oaepparameterspec("sha-256", "mgf1", mgf1parameterspec.sha256, psource.pspecified.default));
        }
        else if (pad.equals("oaepwithsha384andmgf1padding"))
        {
            initfromspec(new oaepparameterspec("sha-384", "mgf1", mgf1parameterspec.sha384, psource.pspecified.default));
        }
        else if (pad.equals("oaepwithsha512andmgf1padding"))
        {
            initfromspec(new oaepparameterspec("sha-512", "mgf1", mgf1parameterspec.sha512, psource.pspecified.default));
        }
        else
        {
            throw new nosuchpaddingexception(padding + " unavailable with elgamal.");
        }
    }

    protected void engineinit(
        int                     opmode,
        key                     key,
        algorithmparameterspec  params,
        securerandom            random) 
    throws invalidkeyexception
    {
        cipherparameters        param;

        if (params == null)
        {
            if (key instanceof elgamalpublickey)
            {
                param = elgamalutil.generatepublickeyparameter((publickey)key);
            }
            else if (key instanceof elgamalprivatekey)
            {
                param = elgamalutil.generateprivatekeyparameter((privatekey)key);
            }
            else
            {
                throw new invalidkeyexception("unknown key type passed to elgamal");
            }
        }
        else
        {
            throw new illegalargumentexception("unknown parameter type.");
        }

        if (random != null)
        {
            param = new parameterswithrandom(param, random);
        }

        switch (opmode)
        {
        case javax.crypto.cipher.encrypt_mode:
        case javax.crypto.cipher.wrap_mode:
            cipher.init(true, param);
            break;
        case javax.crypto.cipher.decrypt_mode:
        case javax.crypto.cipher.unwrap_mode:
            cipher.init(false, param);
            break;
        default:
            throw new invalidparameterexception("unknown opmode " + opmode + " passed to elgamal");
        }
    }

    protected void engineinit(
        int                 opmode,
        key                 key,
        algorithmparameters params,
        securerandom        random) 
    throws invalidkeyexception, invalidalgorithmparameterexception
    {
        throw new invalidalgorithmparameterexception("can't handle parameters in elgamal");
    }

    protected void engineinit(
        int                 opmode,
        key                 key,
        securerandom        random) 
    throws invalidkeyexception
    {
        engineinit(opmode, key, (algorithmparameterspec)null, random);
    }

    protected byte[] engineupdate(
        byte[]  input,
        int     inputoffset,
        int     inputlen) 
    {
        cipher.processbytes(input, inputoffset, inputlen);
        return null;
    }

    protected int engineupdate(
        byte[]  input,
        int     inputoffset,
        int     inputlen,
        byte[]  output,
        int     outputoffset) 
    {
        cipher.processbytes(input, inputoffset, inputlen);
        return 0;
    }

    protected byte[] enginedofinal(
        byte[]  input,
        int     inputoffset,
        int     inputlen) 
        throws illegalblocksizeexception, badpaddingexception
    {
        cipher.processbytes(input, inputoffset, inputlen);
        try
        {
            return cipher.dofinal();
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
        byte[]  out;

        cipher.processbytes(input, inputoffset, inputlen);

        try
        {
            out = cipher.dofinal();
        }
        catch (invalidciphertextexception e)
        {
            throw new badpaddingexception(e.getmessage());
        }

        for (int i = 0; i != out.length; i++)
        {
            output[outputoffset + i] = out[i];
        }

        return out.length;
    }

    /**
     * classes that inherit from us.
     */
    static public class nopadding
        extends cipherspi
    {
        public nopadding()
        {
            super(new elgamalengine());
        }
    }
    
    static public class pkcs1v1_5padding
        extends cipherspi
    {
        public pkcs1v1_5padding()
        {
            super(new pkcs1encoding(new elgamalengine()));
        }
    }
}
