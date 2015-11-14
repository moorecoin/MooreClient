package org.ripple.bouncycastle.crypto;

import org.ripple.bouncycastle.util.strings;

/**
 * super class for all password based encryption (pbe) parameter generator classes.
 */
public abstract class pbeparametersgenerator
{
    protected byte[]  password;
    protected byte[]  salt;
    protected int     iterationcount;

    /**
     * base constructor.
     */
    protected pbeparametersgenerator()
    {
    }

    /**
     * initialise the pbe generator.
     *
     * @param password the password converted into bytes (see below).
     * @param salt the salt to be mixed with the password.
     * @param iterationcount the number of iterations the "mixing" function
     * is to be applied for.
     */
    public void init(
        byte[]  password,
        byte[]  salt,
        int     iterationcount)
    {
        this.password = password;
        this.salt = salt;
        this.iterationcount = iterationcount;
    }

    /**
     * return the password byte array.
     *
     * @return the password byte array.
     */
    public byte[] getpassword()
    {
        return password;
    }

    /**
     * return the salt byte array.
     *
     * @return the salt byte array.
     */
    public byte[] getsalt()
    {
        return salt;
    }

    /**
     * return the iteration count.
     *
     * @return the iteration count.
     */
    public int getiterationcount()
    {
        return iterationcount;
    }

    /**
     * generate derived parameters for a key of length keysize.
     *
     * @param keysize the length, in bits, of the key required.
     * @return a parameters object representing a key.
     */
    public abstract cipherparameters generatederivedparameters(int keysize);

    /**
     * generate derived parameters for a key of length keysize, and
     * an initialisation vector (iv) of length ivsize.
     *
     * @param keysize the length, in bits, of the key required.
     * @param ivsize the length, in bits, of the iv required.
     * @return a parameters object representing a key and an iv.
     */
    public abstract cipherparameters generatederivedparameters(int keysize, int ivsize);

    /**
     * generate derived parameters for a key of length keysize, specifically
     * for use with a mac.
     *
     * @param keysize the length, in bits, of the key required.
     * @return a parameters object representing a key.
     */
    public abstract cipherparameters generatederivedmacparameters(int keysize);

    /**
     * converts a password to a byte array according to the scheme in
     * pkcs5 (ascii, no padding)
     *
     * @param password a character array representing the password.
     * @return a byte array representing the password.
     */
    public static byte[] pkcs5passwordtobytes(
        char[]  password)
    {
        if (password != null)
        {
            byte[]  bytes = new byte[password.length];

            for (int i = 0; i != bytes.length; i++)
            {
                bytes[i] = (byte)password[i];
            }

            return bytes;
        }
        else
        {
            return new byte[0];
        }
    }

    /**
     * converts a password to a byte array according to the scheme in
     * pkcs5 (utf-8, no padding)
     *
     * @param password a character array representing the password.
     * @return a byte array representing the password.
     */
    public static byte[] pkcs5passwordtoutf8bytes(
        char[]  password)
    {
        if (password != null)
        {
            return strings.toutf8bytearray(password);
        }
        else
        {
            return new byte[0];
        }
    }

    /**
     * converts a password to a byte array according to the scheme in
     * pkcs12 (unicode, big endian, 2 zero pad bytes at the end).
     *
     * @param password a character array representing the password.
     * @return a byte array representing the password.
     */
    public static byte[] pkcs12passwordtobytes(
        char[]  password)
    {
        if (password != null && password.length > 0)
        {
                                       // +1 for extra 2 pad bytes.
            byte[]  bytes = new byte[(password.length + 1) * 2];

            for (int i = 0; i != password.length; i ++)
            {
                bytes[i * 2] = (byte)(password[i] >>> 8);
                bytes[i * 2 + 1] = (byte)password[i];
            }

            return bytes;
        }
        else
        {
            return new byte[0];
        }
    }
}
