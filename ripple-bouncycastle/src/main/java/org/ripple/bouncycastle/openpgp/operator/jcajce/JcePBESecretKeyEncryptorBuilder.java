package org.ripple.bouncycastle.openpgp.operator.jcajce;

import java.security.invalidalgorithmparameterexception;
import java.security.invalidkeyexception;
import java.security.provider;
import java.security.securerandom;

import javax.crypto.badpaddingexception;
import javax.crypto.cipher;
import javax.crypto.illegalblocksizeexception;
import javax.crypto.spec.ivparameterspec;

import org.ripple.bouncycastle.jcajce.defaultjcajcehelper;
import org.ripple.bouncycastle.jcajce.namedjcajcehelper;
import org.ripple.bouncycastle.jcajce.providerjcajcehelper;
import org.ripple.bouncycastle.openpgp.pgpexception;
import org.ripple.bouncycastle.openpgp.operator.pbesecretkeyencryptor;
import org.ripple.bouncycastle.openpgp.operator.pgpdigestcalculator;

public class jcepbesecretkeyencryptorbuilder
{
    private operatorhelper helper = new operatorhelper(new defaultjcajcehelper());
    private int encalgorithm;
    private pgpdigestcalculator s2kdigestcalculator;
    private securerandom random;
    private int s2kcount = 0x60;

    public jcepbesecretkeyencryptorbuilder(int encalgorithm)
    {
        this(encalgorithm, new sha1pgpdigestcalculator());
    }

    /**
     * create a secretkeyencryptorbuilder with the s2k count different to the default of 0x60.
     *
     * @param encalgorithm encryption algorithm to use.
     * @param s2kcount iteration count to use for s2k function.
     */
    public jcepbesecretkeyencryptorbuilder(int encalgorithm, int s2kcount)
    {
        this(encalgorithm, new sha1pgpdigestcalculator(), s2kcount);
    }

    /**
     * create a builder which will make encryptors using the passed in digest calculator. if a md5 calculator is
     * passed in the builder will assume the encryptors are for use with version 3 keys.
     *
     * @param encalgorithm  encryption algorithm to use.
     * @param s2kdigestcalculator digest calculator to use.
     */
    public jcepbesecretkeyencryptorbuilder(int encalgorithm, pgpdigestcalculator s2kdigestcalculator)
    {
        this(encalgorithm, s2kdigestcalculator, 0x60);
    }

    /**
     * create an secretkeyencryptorbuilder with the s2k count different to the default of 0x60, and the s2k digest
     * different from sha-1.
     *
     * @param encalgorithm encryption algorithm to use.
     * @param s2kdigestcalculator digest calculator to use.
     * @param s2kcount iteration count to use for s2k function.
     */
    public jcepbesecretkeyencryptorbuilder(int encalgorithm, pgpdigestcalculator s2kdigestcalculator, int s2kcount)
    {
        this.encalgorithm = encalgorithm;
        this.s2kdigestcalculator = s2kdigestcalculator;

        if (s2kcount < 0 || s2kcount > 0xff)
        {
            throw new illegalargumentexception("s2kcount value outside of range 0 to 255.");
        }

        this.s2kcount = s2kcount;
    }

    public jcepbesecretkeyencryptorbuilder setprovider(provider provider)
    {
        this.helper = new operatorhelper(new providerjcajcehelper(provider));

        return this;
    }

    public jcepbesecretkeyencryptorbuilder setprovider(string providername)
    {
        this.helper = new operatorhelper(new namedjcajcehelper(providername));

        return this;
    }

   /**
     * provide a user defined source of randomness.
     *
     * @param random  the secure random to be used.
     * @return  the current builder.
     */
    public jcepbesecretkeyencryptorbuilder setsecurerandom(securerandom random)
    {
        this.random = random;

        return this;
    }

    public pbesecretkeyencryptor build(char[] passphrase)
    {
        if (random == null)
        {
            random = new securerandom();
        }

        return new pbesecretkeyencryptor(encalgorithm, s2kdigestcalculator, s2kcount, random, passphrase)
        {
            private cipher c;
            private byte[] iv;

            public byte[] encryptkeydata(byte[] key, byte[] keydata, int keyoff, int keylen)
                throws pgpexception
            {
                try
                {
                    c = helper.createcipher(pgputil.getsymmetricciphername(this.encalgorithm) + "/cfb/nopadding");

                    c.init(cipher.encrypt_mode, pgputil.makesymmetrickey(this.encalgorithm, key), this.random);

                    iv = c.getiv();

                    return c.dofinal(keydata, keyoff, keylen);
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
                    throw new pgpexception("invalid key: " + e.getmessage(), e);
                }
            }

            public byte[] encryptkeydata(byte[] key, byte[] iv, byte[] keydata, int keyoff, int keylen)
                throws pgpexception
            {
                try
                {
                    c = helper.createcipher(pgputil.getsymmetricciphername(this.encalgorithm) + "/cfb/nopadding");

                    c.init(cipher.encrypt_mode, pgputil.makesymmetrickey(this.encalgorithm, key), new ivparameterspec(iv));

                    this.iv = iv;

                    return c.dofinal(keydata, keyoff, keylen);
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
                    throw new pgpexception("invalid key: " + e.getmessage(), e);
                }
                catch (invalidalgorithmparameterexception e)
                {
                    throw new pgpexception("invalid iv: " + e.getmessage(), e);
                }
            }

            public byte[] getcipheriv()
            {
                return iv;
            }
        };
    }
}
