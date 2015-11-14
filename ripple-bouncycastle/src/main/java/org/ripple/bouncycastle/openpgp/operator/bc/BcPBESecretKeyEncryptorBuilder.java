package org.ripple.bouncycastle.openpgp.operator.bc;

import java.security.securerandom;

import org.ripple.bouncycastle.crypto.blockcipher;
import org.ripple.bouncycastle.crypto.bufferedblockcipher;
import org.ripple.bouncycastle.crypto.invalidciphertextexception;
import org.ripple.bouncycastle.openpgp.pgpexception;
import org.ripple.bouncycastle.openpgp.operator.pbesecretkeyencryptor;
import org.ripple.bouncycastle.openpgp.operator.pgpdigestcalculator;

public class bcpbesecretkeyencryptorbuilder
{
    private int encalgorithm;
    private pgpdigestcalculator s2kdigestcalculator;
    private securerandom random;
    private int s2kcount = 0x60;

    public bcpbesecretkeyencryptorbuilder(int encalgorithm)
    {
        this(encalgorithm, new sha1pgpdigestcalculator());
    }

    /**
     * create an secretkeyencryptorbuilder with the s2k count different to the default of 0x60.
     *
     * @param encalgorithm encryption algorithm to use.
     * @param s2kcount iteration count to use for s2k function.
     */
    public bcpbesecretkeyencryptorbuilder(int encalgorithm, int s2kcount)
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
    public bcpbesecretkeyencryptorbuilder(int encalgorithm, pgpdigestcalculator s2kdigestcalculator)
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
    public bcpbesecretkeyencryptorbuilder(int encalgorithm, pgpdigestcalculator s2kdigestcalculator, int s2kcount)
    {
        this.encalgorithm = encalgorithm;
        this.s2kdigestcalculator = s2kdigestcalculator;

        if (s2kcount < 0 || s2kcount > 0xff)
        {
            throw new illegalargumentexception("s2kcount value outside of range 0 to 255.");
        }

        this.s2kcount = s2kcount;
    }

    /**
     * provide a user defined source of randomness.
     *
     * @param random  the secure random to be used.
     * @return  the current builder.
     */
    public bcpbesecretkeyencryptorbuilder setsecurerandom(securerandom random)
    {
        this.random = random;

        return this;
    }

    public pbesecretkeyencryptor build(char[] passphrase)
    {
        if (this.random == null)
        {
            this.random = new securerandom();
        }

        return new pbesecretkeyencryptor(encalgorithm, s2kdigestcalculator, s2kcount, this.random, passphrase)
        {
            private byte[] iv;

            public byte[] encryptkeydata(byte[] key, byte[] keydata, int keyoff, int keylen)
                throws pgpexception
            {
                return encryptkeydata(key, null, keydata, keyoff, keylen);
            }

            public byte[] encryptkeydata(byte[] key, byte[] iv, byte[] keydata, int keyoff, int keylen)
                throws pgpexception
            {
                try
                {
                    blockcipher engine = bcimplprovider.createblockcipher(this.encalgorithm);

                    if (iv != null)
                    {    // to deal with v3 key encryption
                        this.iv = iv;
                    }
                    else
                    {
                        if (this.random == null)
                        {
                            this.random = new securerandom();
                        }

                        this.iv = iv = new byte[engine.getblocksize()];

                        this.random.nextbytes(iv);
                    }

                    bufferedblockcipher c = bcutil.createsymmetrickeywrapper(true, engine, key, iv);

                    byte[] out = new byte[keylen];
                    int    outlen = c.processbytes(keydata, keyoff, keylen, out, 0);

                    outlen += c.dofinal(out, outlen);

                    return out;
                }
                catch (invalidciphertextexception e)
                {
                    throw new pgpexception("decryption failed: " + e.getmessage(), e);
                }
            }

            public byte[] getcipheriv()
            {
                return iv;
            }
        };
    }
}
