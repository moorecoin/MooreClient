package org.ripple.bouncycastle.openpgp.operator.jcajce;

import java.math.biginteger;
import java.security.invalidkeyexception;
import java.security.privatekey;
import java.security.provider;

import javax.crypto.cipher;

import org.ripple.bouncycastle.jcajce.defaultjcajcehelper;
import org.ripple.bouncycastle.jcajce.namedjcajcehelper;
import org.ripple.bouncycastle.jcajce.providerjcajcehelper;
import org.ripple.bouncycastle.jce.interfaces.elgamalkey;
import org.ripple.bouncycastle.openpgp.pgpexception;
import org.ripple.bouncycastle.openpgp.pgpprivatekey;
import org.ripple.bouncycastle.openpgp.pgppublickey;
import org.ripple.bouncycastle.openpgp.operator.pgpdatadecryptor;
import org.ripple.bouncycastle.openpgp.operator.publickeydatadecryptorfactory;

public class jcepublickeydatadecryptorfactorybuilder
{
    private operatorhelper helper = new operatorhelper(new defaultjcajcehelper());
    private operatorhelper contenthelper = new operatorhelper(new defaultjcajcehelper());
    private jcapgpkeyconverter keyconverter = new jcapgpkeyconverter();

    public jcepublickeydatadecryptorfactorybuilder()
    {
    }

    /**
     * set the provider object to use for creating cryptographic primitives in the resulting factory the builder produces.
     *
     * @param provider  provider object for cryptographic primitives.
     * @return  the current builder.
     */
    public jcepublickeydatadecryptorfactorybuilder setprovider(provider provider)
    {
        this.helper = new operatorhelper(new providerjcajcehelper(provider));
        keyconverter.setprovider(provider);
        this.contenthelper = helper;

        return this;
    }

    /**
     * set the provider name to use for creating cryptographic primitives in the resulting factory the builder produces.
     *
     * @param providername  the name of the provider to reference for cryptographic primitives.
     * @return  the current builder.
     */
    public jcepublickeydatadecryptorfactorybuilder setprovider(string providername)
    {
        this.helper = new operatorhelper(new namedjcajcehelper(providername));
        keyconverter.setprovider(providername);
        this.contenthelper = helper;

        return this;
    }

    public jcepublickeydatadecryptorfactorybuilder setcontentprovider(provider provider)
    {
        this.contenthelper = new operatorhelper(new providerjcajcehelper(provider));

        return this;
    }

    public jcepublickeydatadecryptorfactorybuilder setcontentprovider(string providername)
    {
        this.contenthelper = new operatorhelper(new namedjcajcehelper(providername));

        return this;
    }

    public publickeydatadecryptorfactory build(final privatekey privkey)
    {
         return new publickeydatadecryptorfactory()
         {
             public byte[] recoversessiondata(int keyalgorithm, biginteger[] seckeydata)
                 throws pgpexception
             {
                 return decryptsessiondata(keyalgorithm, privkey, seckeydata);
             }

             public pgpdatadecryptor createdatadecryptor(boolean withintegritypacket, int encalgorithm, byte[] key)
                 throws pgpexception
             {
                 return contenthelper.createdatadecryptor(withintegritypacket, encalgorithm, key);
             }
         };
    }


    public publickeydatadecryptorfactory build(final pgpprivatekey privkey)
    {
         return new publickeydatadecryptorfactory()
         {
             public byte[] recoversessiondata(int keyalgorithm, biginteger[] seckeydata)
                 throws pgpexception
             {
                 return decryptsessiondata(keyalgorithm, keyconverter.getprivatekey(privkey), seckeydata);
             }

             public pgpdatadecryptor createdatadecryptor(boolean withintegritypacket, int encalgorithm, byte[] key)
                 throws pgpexception
             {
                 return contenthelper.createdatadecryptor(withintegritypacket, encalgorithm, key);
             }
         };
    }

    private byte[] decryptsessiondata(int keyalgorithm, privatekey privkey, biginteger[] seckeydata)
        throws pgpexception
    {
        cipher c1 = helper.createpublickeycipher(keyalgorithm);

        try
        {
            c1.init(cipher.decrypt_mode, privkey);
        }
        catch (invalidkeyexception e)
        {
            throw new pgpexception("error setting asymmetric cipher", e);
        }

        if (keyalgorithm == pgppublickey.rsa_encrypt
            || keyalgorithm == pgppublickey.rsa_general)
        {
            byte[] bi = seckeydata[0].tobytearray();

            if (bi[0] == 0)
            {
                c1.update(bi, 1, bi.length - 1);
            }
            else
            {
                c1.update(bi);
            }
        }
        else
        {
            elgamalkey k = (elgamalkey)privkey;
            int size = (k.getparameters().getp().bitlength() + 7) / 8;
            byte[] tmp = new byte[size];

            byte[] bi = seckeydata[0].tobytearray();
            if (bi.length > size)
            {
                c1.update(bi, 1, bi.length - 1);
            }
            else
            {
                system.arraycopy(bi, 0, tmp, tmp.length - bi.length, bi.length);
                c1.update(tmp);
            }

            bi = seckeydata[1].tobytearray();
            for (int i = 0; i != tmp.length; i++)
            {
                tmp[i] = 0;
            }

            if (bi.length > size)
            {
                c1.update(bi, 1, bi.length - 1);
            }
            else
            {
                system.arraycopy(bi, 0, tmp, tmp.length - bi.length, bi.length);
                c1.update(tmp);
            }
        }

        byte[] plain;
        try
        {
            plain = c1.dofinal();
        }
        catch (exception e)
        {
            throw new pgpexception("exception decrypting session data", e);
        }

        return plain;
    }
}
