package org.ripple.bouncycastle.jcajce.provider.asymmetric.util;

import java.security.algorithmparameters;
import java.security.invalidkeyexception;
import java.security.key;
import java.security.keyfactory;
import java.security.nosuchalgorithmexception;
import java.security.nosuchproviderexception;
import java.security.privatekey;
import java.security.spec.invalidkeyspecexception;
import java.security.spec.pkcs8encodedkeyspec;
import java.security.spec.x509encodedkeyspec;

import javax.crypto.badpaddingexception;
import javax.crypto.cipher;
import javax.crypto.cipherspi;
import javax.crypto.illegalblocksizeexception;
import javax.crypto.nosuchpaddingexception;
import javax.crypto.spec.ivparameterspec;
import javax.crypto.spec.pbeparameterspec;
import javax.crypto.spec.rc2parameterspec;
import javax.crypto.spec.rc5parameterspec;
import javax.crypto.spec.secretkeyspec;

import org.ripple.bouncycastle.asn1.pkcs.privatekeyinfo;
import org.ripple.bouncycastle.crypto.invalidciphertextexception;
import org.ripple.bouncycastle.crypto.wrapper;
import org.ripple.bouncycastle.jce.provider.bouncycastleprovider;

public abstract class basecipherspi
    extends cipherspi
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


    protected algorithmparameters     engineparams = null;

    protected wrapper                 wrapengine = null;

    private int                       ivsize;
    private byte[]                    iv;

    protected basecipherspi()
    {
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
    throws invalidkeyexception
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
}
