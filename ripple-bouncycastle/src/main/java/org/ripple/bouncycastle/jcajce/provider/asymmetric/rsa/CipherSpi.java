package org.ripple.bouncycastle.jcajce.provider.asymmetric.rsa;

import java.io.bytearrayoutputstream;
import java.security.algorithmparameters;
import java.security.invalidalgorithmparameterexception;
import java.security.invalidkeyexception;
import java.security.invalidparameterexception;
import java.security.key;
import java.security.nosuchalgorithmexception;
import java.security.securerandom;
import java.security.interfaces.rsaprivatekey;
import java.security.interfaces.rsapublickey;
import java.security.spec.algorithmparameterspec;
import java.security.spec.invalidparameterspecexception;
import java.security.spec.mgf1parameterspec;

import javax.crypto.badpaddingexception;
import javax.crypto.cipher;
import javax.crypto.illegalblocksizeexception;
import javax.crypto.nosuchpaddingexception;
import javax.crypto.spec.oaepparameterspec;
import javax.crypto.spec.psource;

import org.ripple.bouncycastle.asn1.pkcs.pkcsobjectidentifiers;
import org.ripple.bouncycastle.crypto.asymmetricblockcipher;
import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.digest;
import org.ripple.bouncycastle.crypto.invalidciphertextexception;
import org.ripple.bouncycastle.crypto.encodings.iso9796d1encoding;
import org.ripple.bouncycastle.crypto.encodings.oaepencoding;
import org.ripple.bouncycastle.crypto.encodings.pkcs1encoding;
import org.ripple.bouncycastle.crypto.engines.rsablindedengine;
import org.ripple.bouncycastle.crypto.params.parameterswithrandom;
import org.ripple.bouncycastle.jcajce.provider.asymmetric.util.basecipherspi;
import org.ripple.bouncycastle.jcajce.provider.util.digestfactory;
import org.ripple.bouncycastle.jce.provider.bouncycastleprovider;
import org.ripple.bouncycastle.util.strings;

public class cipherspi
    extends basecipherspi
{
    private asymmetricblockcipher cipher;
    private algorithmparameterspec paramspec;
    private algorithmparameters engineparams;
    private boolean                 publickeyonly = false;
    private boolean                 privatekeyonly = false;
    private bytearrayoutputstream bout = new bytearrayoutputstream();

    public cipherspi(
        asymmetricblockcipher engine)
    {
        cipher = engine;
    }

    public cipherspi(
        oaepparameterspec pspec)
    {
        try
        {
            initfromspec(pspec);
        }
        catch (nosuchpaddingexception e)
        {
            throw new illegalargumentexception(e.getmessage());
        }
    }

    public cipherspi(
        boolean publickeyonly,
        boolean privatekeyonly,
        asymmetricblockcipher engine)
    {
        this.publickeyonly = publickeyonly;
        this.privatekeyonly = privatekeyonly;
        cipher = engine;
    }
     
    private void initfromspec(
        oaepparameterspec pspec)
        throws nosuchpaddingexception
    {
        mgf1parameterspec mgfparams = (mgf1parameterspec)pspec.getmgfparameters();
        digest digest = digestfactory.getdigest(mgfparams.getdigestalgorithm());
        
        if (digest == null)
        {
            throw new nosuchpaddingexception("no match on oaep constructor for digest algorithm: "+ mgfparams.getdigestalgorithm());
        }

        cipher = new oaepencoding(new rsablindedengine(), digest, ((psource.pspecified)pspec.getpsource()).getvalue());
        paramspec = pspec;
    }
    
    protected int enginegetblocksize() 
    {
        try
        {
            return cipher.getinputblocksize();
        }
        catch (nullpointerexception e)
        {
            throw new illegalstateexception("rsa cipher not initialised");
        }
    }

    protected int enginegetkeysize(
        key key)
    {
        if (key instanceof rsaprivatekey)
        {
            rsaprivatekey k = (rsaprivatekey)key;

            return k.getmodulus().bitlength();
        }
        else if (key instanceof rsapublickey)
        {
            rsapublickey k = (rsapublickey)key;

            return k.getmodulus().bitlength();
        }

        throw new illegalargumentexception("not an rsa key!");
    }

    protected int enginegetoutputsize(
        int     inputlen) 
    {
        try
        {
            return cipher.getoutputblocksize();
        }
        catch (nullpointerexception e)
        {
            throw new illegalstateexception("rsa cipher not initialised");
        }
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
        string mode)
        throws nosuchalgorithmexception
    {
        string md = strings.touppercase(mode);
        
        if (md.equals("none") || md.equals("ecb"))
        {
            return;
        }
        
        if (md.equals("1"))
        {
            privatekeyonly = true;
            publickeyonly = false;
            return;
        }
        else if (md.equals("2"))
        {
            privatekeyonly = false;
            publickeyonly = true;
            return;
        }
        
        throw new nosuchalgorithmexception("can't support mode " + mode);
    }

    protected void enginesetpadding(
        string padding)
        throws nosuchpaddingexception
    {
        string pad = strings.touppercase(padding);

        if (pad.equals("nopadding"))
        {
            cipher = new rsablindedengine();
        }
        else if (pad.equals("pkcs1padding"))
        {
            cipher = new pkcs1encoding(new rsablindedengine());
        }
        else if (pad.equals("iso9796-1padding"))
        {
            cipher = new iso9796d1encoding(new rsablindedengine());
        }
        else if (pad.equals("oaepwithmd5andmgf1padding"))
        {
            initfromspec(new oaepparameterspec("md5", "mgf1", new mgf1parameterspec("md5"), psource.pspecified.default));
        }
        else if (pad.equals("oaeppadding"))
        {
            initfromspec(oaepparameterspec.default);
        }
        else if (pad.equals("oaepwithsha1andmgf1padding") || pad.equals("oaepwithsha-1andmgf1padding"))
        {
            initfromspec(oaepparameterspec.default);
        }
        else if (pad.equals("oaepwithsha224andmgf1padding") || pad.equals("oaepwithsha-224andmgf1padding"))
        {
            initfromspec(new oaepparameterspec("sha-224", "mgf1", new mgf1parameterspec("sha-224"), psource.pspecified.default));
        }
        else if (pad.equals("oaepwithsha256andmgf1padding") || pad.equals("oaepwithsha-256andmgf1padding"))
        {
            initfromspec(new oaepparameterspec("sha-256", "mgf1", mgf1parameterspec.sha256, psource.pspecified.default));
        }
        else if (pad.equals("oaepwithsha384andmgf1padding") || pad.equals("oaepwithsha-384andmgf1padding"))
        {
            initfromspec(new oaepparameterspec("sha-384", "mgf1", mgf1parameterspec.sha384, psource.pspecified.default));
        }
        else if (pad.equals("oaepwithsha512andmgf1padding") || pad.equals("oaepwithsha-512andmgf1padding"))
        {
            initfromspec(new oaepparameterspec("sha-512", "mgf1", mgf1parameterspec.sha512, psource.pspecified.default));
        }
        else
        {
            throw new nosuchpaddingexception(padding + " unavailable with rsa.");
        }
    }

    protected void engineinit(
        int                     opmode,
        key key,
        algorithmparameterspec params,
        securerandom random)
    throws invalidkeyexception, invalidalgorithmparameterexception
    {
        cipherparameters param;

        if (params == null || params instanceof oaepparameterspec)
        {
            if (key instanceof rsapublickey)
            {
                if (privatekeyonly && opmode == cipher.encrypt_mode)
                {
                    throw new invalidkeyexception(
                                "mode 1 requires rsaprivatekey");
                }

                param = rsautil.generatepublickeyparameter((rsapublickey)key);
            }
            else if (key instanceof rsaprivatekey)
            {
                if (publickeyonly && opmode == cipher.encrypt_mode)
                {
                    throw new invalidkeyexception(
                                "mode 2 requires rsapublickey");
                }

                param = rsautil.generateprivatekeyparameter((rsaprivatekey)key);
            }
            else
            {
                throw new invalidkeyexception("unknown key type passed to rsa");
            }
            
            if (params != null)
            {
                oaepparameterspec spec = (oaepparameterspec)params;
                
                paramspec = params;
                
                if (!spec.getmgfalgorithm().equalsignorecase("mgf1") && !spec.getmgfalgorithm().equals(pkcsobjectidentifiers.id_mgf1.getid()))
                {
                    throw new invalidalgorithmparameterexception("unknown mask generation function specified");
                }
                
                if (!(spec.getmgfparameters() instanceof mgf1parameterspec))
                {
                    throw new invalidalgorithmparameterexception("unkown mgf parameters");
                }
    
                digest digest = digestfactory.getdigest(spec.getdigestalgorithm());

                if (digest == null)
                {
                    throw new invalidalgorithmparameterexception("no match on digest algorithm: "+ spec.getdigestalgorithm());
                }

                mgf1parameterspec mgfparams = (mgf1parameterspec)spec.getmgfparameters();
                digest mgfdigest = digestfactory.getdigest(mgfparams.getdigestalgorithm());
                
                if (mgfdigest == null)
                {
                    throw new invalidalgorithmparameterexception("no match on mgf digest algorithm: "+ mgfparams.getdigestalgorithm());
                }
                
                cipher = new oaepencoding(new rsablindedengine(), digest, mgfdigest, ((psource.pspecified)spec.getpsource()).getvalue());
            }
        }
        else
        {
            throw new illegalargumentexception("unknown parameter type.");
        }

        if (!(cipher instanceof rsablindedengine))
        {
            if (random != null)
            {
                param = new parameterswithrandom(param, random);
            }
            else
            {
                param = new parameterswithrandom(param, new securerandom());
            }
        }

        bout.reset();

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
            throw new invalidparameterexception("unknown opmode " + opmode + " passed to rsa");
        }
    }

    protected void engineinit(
        int                 opmode,
        key key,
        algorithmparameters params,
        securerandom random)
    throws invalidkeyexception, invalidalgorithmparameterexception
    {
        algorithmparameterspec paramspec = null;

        if (params != null)
        {
            try
            {
                paramspec = params.getparameterspec(oaepparameterspec.class);
            }
            catch (invalidparameterspecexception e)
            {
                throw new invalidalgorithmparameterexception("cannot recognise parameters: " + e.tostring(), e);
            }
        }

        engineparams = params;
        engineinit(opmode, key, paramspec, random);
    }

    protected void engineinit(
        int                 opmode,
        key key,
        securerandom random)
    throws invalidkeyexception
    {
        try
        {
            engineinit(opmode, key, (algorithmparameterspec)null, random);
        }
        catch (invalidalgorithmparameterexception e)
        {
            // this shouldn't happen
            throw new invalidkeyexception("eeeek! " + e.tostring(), e);
        }
    }

    protected byte[] engineupdate(
        byte[]  input,
        int     inputoffset,
        int     inputlen) 
    {
        bout.write(input, inputoffset, inputlen);

        if (cipher instanceof rsablindedengine)
        {
            if (bout.size() > cipher.getinputblocksize() + 1)
            {
                throw new arrayindexoutofboundsexception("too much data for rsa block");
            }
        }
        else
        {
            if (bout.size() > cipher.getinputblocksize())
            {
                throw new arrayindexoutofboundsexception("too much data for rsa block");
            }
        }

        return null;
    }

    protected int engineupdate(
        byte[]  input,
        int     inputoffset,
        int     inputlen,
        byte[]  output,
        int     outputoffset) 
    {
        bout.write(input, inputoffset, inputlen);

        if (cipher instanceof rsablindedengine)
        {
            if (bout.size() > cipher.getinputblocksize() + 1)
            {
                throw new arrayindexoutofboundsexception("too much data for rsa block");
            }
        }
        else
        {
            if (bout.size() > cipher.getinputblocksize())
            {
                throw new arrayindexoutofboundsexception("too much data for rsa block");
            }
        }

        return 0;
    }

    protected byte[] enginedofinal(
        byte[]  input,
        int     inputoffset,
        int     inputlen) 
        throws illegalblocksizeexception, badpaddingexception
    {
        if (input != null)
        {
            bout.write(input, inputoffset, inputlen);
        }

        if (cipher instanceof rsablindedengine)
        {
            if (bout.size() > cipher.getinputblocksize() + 1)
            {
                throw new arrayindexoutofboundsexception("too much data for rsa block");
            }
        }
        else
        {
            if (bout.size() > cipher.getinputblocksize())
            {
                throw new arrayindexoutofboundsexception("too much data for rsa block");
            }
        }

        try
        {
            byte[]  bytes = bout.tobytearray();

            bout.reset();

            return cipher.processblock(bytes, 0, bytes.length);
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
        if (input != null)
        {
            bout.write(input, inputoffset, inputlen);
        }

        if (cipher instanceof rsablindedengine)
        {
            if (bout.size() > cipher.getinputblocksize() + 1)
            {
                throw new arrayindexoutofboundsexception("too much data for rsa block");
            }
        }
        else
        {
            if (bout.size() > cipher.getinputblocksize())
            {
                throw new arrayindexoutofboundsexception("too much data for rsa block");
            }
        }

        byte[]  out;

        try
        {
            byte[]  bytes = bout.tobytearray();

            out = cipher.processblock(bytes, 0, bytes.length);
        }
        catch (invalidciphertextexception e)
        {
            throw new badpaddingexception(e.getmessage());
        }
        finally
        {
            bout.reset();
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
            super(new rsablindedengine());
        }
    }

    static public class pkcs1v1_5padding
        extends cipherspi
    {
        public pkcs1v1_5padding()
        {
            super(new pkcs1encoding(new rsablindedengine()));
        }
    }

    static public class pkcs1v1_5padding_privateonly
        extends cipherspi
    {
        public pkcs1v1_5padding_privateonly()
        {
            super(false, true, new pkcs1encoding(new rsablindedengine()));
        }
    }

    static public class pkcs1v1_5padding_publiconly
        extends cipherspi
    {
        public pkcs1v1_5padding_publiconly()
        {
            super(true, false, new pkcs1encoding(new rsablindedengine()));
        }
    }

    static public class oaeppadding
        extends cipherspi
    {
        public oaeppadding()
        {
            super(oaepparameterspec.default);
        }
    }
    
    static public class iso9796d1padding
        extends cipherspi
    {
        public iso9796d1padding()
        {
            super(new iso9796d1encoding(new rsablindedengine()));
        }
    }
}
