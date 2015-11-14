package org.ripple.bouncycastle.crypto.params;

public class desparameters
    extends keyparameter
{
    public desparameters(
        byte[]  key)
    {
        super(key);

        if (isweakkey(key, 0))
        {
            throw new illegalargumentexception("attempt to create weak des key");
        }
    }

    /*
     * des key length in bytes.
     */
    static public final int des_key_length = 8;

    /*
     * table of weak and semi-weak keys taken from schneier pp281
     */
    static private final int n_des_weak_keys = 16;

    static private byte[] des_weak_keys =
    {
        /* weak keys */
        (byte)0x01,(byte)0x01,(byte)0x01,(byte)0x01, (byte)0x01,(byte)0x01,(byte)0x01,(byte)0x01,
        (byte)0x1f,(byte)0x1f,(byte)0x1f,(byte)0x1f, (byte)0x0e,(byte)0x0e,(byte)0x0e,(byte)0x0e,
        (byte)0xe0,(byte)0xe0,(byte)0xe0,(byte)0xe0, (byte)0xf1,(byte)0xf1,(byte)0xf1,(byte)0xf1,
        (byte)0xfe,(byte)0xfe,(byte)0xfe,(byte)0xfe, (byte)0xfe,(byte)0xfe,(byte)0xfe,(byte)0xfe,

        /* semi-weak keys */
        (byte)0x01,(byte)0xfe,(byte)0x01,(byte)0xfe, (byte)0x01,(byte)0xfe,(byte)0x01,(byte)0xfe,
        (byte)0x1f,(byte)0xe0,(byte)0x1f,(byte)0xe0, (byte)0x0e,(byte)0xf1,(byte)0x0e,(byte)0xf1,
        (byte)0x01,(byte)0xe0,(byte)0x01,(byte)0xe0, (byte)0x01,(byte)0xf1,(byte)0x01,(byte)0xf1,
        (byte)0x1f,(byte)0xfe,(byte)0x1f,(byte)0xfe, (byte)0x0e,(byte)0xfe,(byte)0x0e,(byte)0xfe,
        (byte)0x01,(byte)0x1f,(byte)0x01,(byte)0x1f, (byte)0x01,(byte)0x0e,(byte)0x01,(byte)0x0e,
        (byte)0xe0,(byte)0xfe,(byte)0xe0,(byte)0xfe, (byte)0xf1,(byte)0xfe,(byte)0xf1,(byte)0xfe,
        (byte)0xfe,(byte)0x01,(byte)0xfe,(byte)0x01, (byte)0xfe,(byte)0x01,(byte)0xfe,(byte)0x01,
        (byte)0xe0,(byte)0x1f,(byte)0xe0,(byte)0x1f, (byte)0xf1,(byte)0x0e,(byte)0xf1,(byte)0x0e,
        (byte)0xe0,(byte)0x01,(byte)0xe0,(byte)0x01, (byte)0xf1,(byte)0x01,(byte)0xf1,(byte)0x01,
        (byte)0xfe,(byte)0x1f,(byte)0xfe,(byte)0x1f, (byte)0xfe,(byte)0x0e,(byte)0xfe,(byte)0x0e,
        (byte)0x1f,(byte)0x01,(byte)0x1f,(byte)0x01, (byte)0x0e,(byte)0x01,(byte)0x0e,(byte)0x01,
        (byte)0xfe,(byte)0xe0,(byte)0xfe,(byte)0xe0, (byte)0xfe,(byte)0xf1,(byte)0xfe,(byte)0xf1
    };

    /**
     * des has 16 weak keys.  this method will check
     * if the given des key material is weak or semi-weak.
     * key material that is too short is regarded as weak.
     * <p>
     * see <a href="http://www.counterpane.com/applied.html">"applied
     * cryptography"</a> by bruce schneier for more information.
     *
     * @return true if the given des key material is weak or semi-weak,
     *     false otherwise.
     */
    public static boolean isweakkey(
        byte[] key,
        int offset)
    {
        if (key.length - offset < des_key_length)
        {
            throw new illegalargumentexception("key material too short.");
        }

        nextkey: for (int i = 0; i < n_des_weak_keys; i++)
        {
            for (int j = 0; j < des_key_length; j++)
            {
                if (key[j + offset] != des_weak_keys[i * des_key_length + j])
                {
                    continue nextkey;
                }
            }

            return true;
        }
        return false;
    }

    /**
     * des keys use the lsb as the odd parity bit.  this can
     * be used to check for corrupt keys.
     *
     * @param bytes the byte array to set the parity on.
     */
    public static void setoddparity(
        byte[] bytes)
    {
        for (int i = 0; i < bytes.length; i++)
        {
            int b = bytes[i];
            bytes[i] = (byte)((b & 0xfe) |
                            ((((b >> 1) ^
                            (b >> 2) ^
                            (b >> 3) ^
                            (b >> 4) ^
                            (b >> 5) ^
                            (b >> 6) ^
                            (b >> 7)) ^ 0x01) & 0x01));
        }
    }
}
