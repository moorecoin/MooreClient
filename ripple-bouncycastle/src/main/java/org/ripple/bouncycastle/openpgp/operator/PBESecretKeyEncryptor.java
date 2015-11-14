package org.ripple.bouncycastle.openpgp.operator;

import java.security.securerandom;

import org.ripple.bouncycastle.bcpg.s2k;
import org.ripple.bouncycastle.openpgp.pgpexception;

public abstract class pbesecretkeyencryptor
{
    protected int encalgorithm;
    protected char[] passphrase;
    protected pgpdigestcalculator s2kdigestcalculator;
    protected int s2kcount;
    protected s2k s2k;

    protected securerandom random;

    protected pbesecretkeyencryptor(int encalgorithm, pgpdigestcalculator s2kdigestcalculator, securerandom random, char[] passphrase)
    {
        this(encalgorithm, s2kdigestcalculator, 0x60, random, passphrase);
    }

    protected pbesecretkeyencryptor(int encalgorithm, pgpdigestcalculator s2kdigestcalculator, int s2kcount, securerandom random, char[] passphrase)
    {
        this.encalgorithm = encalgorithm;
        this.passphrase = passphrase;
        this.random = random;
        this.s2kdigestcalculator = s2kdigestcalculator;

        if (s2kcount < 0 || s2kcount > 0xff)
        {
            throw new illegalargumentexception("s2kcount value outside of range 0 to 255.");
        }

        this.s2kcount = s2kcount;
    }

    public int getalgorithm()
    {
        return encalgorithm;
    }

    public int gethashalgorithm()
    {
        if (s2kdigestcalculator != null)
        {
            return s2kdigestcalculator.getalgorithm();
        }

        return -1;
    }

    public byte[] getkey()
        throws pgpexception
    {
        return pgputil.makekeyfrompassphrase(s2kdigestcalculator, encalgorithm, s2k, passphrase);
    }

    public s2k gets2k()
    {
        return s2k;
    }

    /**
     * key encryption method invoked for v4 keys and greater.
     *
     * @param keydata raw key data
     * @param keyoff offset into rawe key data
     * @param keylen length of key data to use.
     * @return an encryption of the passed in keydata.
     * @throws pgpexception on error in the underlying encryption process.
     */
    public byte[] encryptkeydata(byte[] keydata, int keyoff, int keylen)
        throws pgpexception
    {
        if (s2k == null)
        {
            byte[]        iv = new byte[8];

            random.nextbytes(iv);

            s2k = new s2k(s2kdigestcalculator.getalgorithm(), iv, s2kcount);
        }

        return encryptkeydata(getkey(), keydata, keyoff, keylen);
    }

    public abstract byte[] encryptkeydata(byte[] key, byte[] keydata, int keyoff, int keylen)
        throws pgpexception;

    /**
     * encrypt the passed in keydata using the key and the iv provided.
     * <p>
     * this method is only used for processing version 3 keys.
     * </p>
     */
    public byte[] encryptkeydata(byte[] key, byte[] iv, byte[] keydata, int keyoff, int keylen)
        throws pgpexception
    {
        throw new pgpexception("encryption of version 3 keys not supported.");
    }

    public abstract byte[] getcipheriv();
}
