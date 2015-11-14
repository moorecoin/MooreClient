package org.ripple.bouncycastle.openpgp.operator.jcajce;

import java.security.invalidkeyexception;
import java.security.key;
import java.security.provider;
import java.security.securerandom;

import javax.crypto.badpaddingexception;
import javax.crypto.cipher;
import javax.crypto.illegalblocksizeexception;

import org.ripple.bouncycastle.jcajce.defaultjcajcehelper;
import org.ripple.bouncycastle.jcajce.namedjcajcehelper;
import org.ripple.bouncycastle.jcajce.providerjcajcehelper;
import org.ripple.bouncycastle.openpgp.pgpexception;
import org.ripple.bouncycastle.openpgp.pgppublickey;
import org.ripple.bouncycastle.openpgp.operator.publickeykeyencryptionmethodgenerator;

public class jcepublickeykeyencryptionmethodgenerator
    extends publickeykeyencryptionmethodgenerator
{
    private operatorhelper helper = new operatorhelper(new defaultjcajcehelper());
    private securerandom random;
    private jcapgpkeyconverter keyconverter = new jcapgpkeyconverter();

    /**
     * create a public key encryption method generator with the method to be based on the passed in key.
     *
     * @param key   the public key to use for encryption.
     */
    public jcepublickeykeyencryptionmethodgenerator(pgppublickey key)
    {
        super(key);
    }

    public jcepublickeykeyencryptionmethodgenerator setprovider(provider provider)
    {
        this.helper = new operatorhelper(new providerjcajcehelper(provider));

        keyconverter.setprovider(provider);

        return this;
    }

    public jcepublickeykeyencryptionmethodgenerator setprovider(string providername)
    {
        this.helper = new operatorhelper(new namedjcajcehelper(providername));

        keyconverter.setprovider(providername);

        return this;
    }

    /**
     * provide a user defined source of randomness.
     *
     * @param random  the secure random to be used.
     * @return  the current generator.
     */
    public jcepublickeykeyencryptionmethodgenerator setsecurerandom(securerandom random)
    {
        this.random = random;

        return this;
    }

    protected byte[] encryptsessioninfo(pgppublickey pubkey, byte[] sessioninfo)
        throws pgpexception
    {
        try
        {
            cipher c = helper.createpublickeycipher(pubkey.getalgorithm());

            key key = keyconverter.getpublickey(pubkey);

            c.init(cipher.encrypt_mode, key, random);

            return c.dofinal(sessioninfo);
        }
        catch (illegalblocksizeexception e)
        {
            throw new pgpexception("illegal block size: " + e.getmessage(), e);
        }
        catch (badpaddingexception e)
        {
            throw new pgpexception("bad padding: " + e.getmessage(), e);
        }
        catch (invalidkeyexception e)
        {
            throw new pgpexception("key invalid: " + e.getmessage(), e);
        }
    }
}
