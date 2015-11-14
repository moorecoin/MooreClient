package org.ripple.bouncycastle.crypto.params;

public class desedeparameters
    extends desparameters
{
    /*
     * des-ede key length in bytes.
     */
    static public final int des_ede_key_length = 24;

    public desedeparameters(
        byte[]  key)
    {
        super(key);

        if (isweakkey(key, 0, key.length))
        {
            throw new illegalargumentexception("attempt to create weak desede key");
        }
    }

    /**
     * return true if the passed in key is a des-ede weak key.
     *
     * @param key bytes making up the key
     * @param offset offset into the byte array the key starts at
     * @param length number of bytes making up the key
     */
    public static boolean isweakkey(
        byte[]  key,
        int     offset,
        int     length)
    {
        for (int i = offset; i < length; i += des_key_length)
        {
            if (desparameters.isweakkey(key, i))
            {
                return true;
            }
        }

        return false;
    }

    /**
     * return true if the passed in key is a des-ede weak key.
     *
     * @param key bytes making up the key
     * @param offset offset into the byte array the key starts at
     */
    public static boolean isweakkey(
        byte[]  key,
        int     offset)
    {
        return isweakkey(key, offset, key.length - offset);
    }
}
