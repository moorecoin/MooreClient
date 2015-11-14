package org.ripple.bouncycastle.crypto.prng.drbg;

import java.util.hashtable;

import org.ripple.bouncycastle.crypto.digest;
import org.ripple.bouncycastle.crypto.mac;
import org.ripple.bouncycastle.util.integers;

class utils
{
    static final hashtable maxsecuritystrengths = new hashtable();

    static
    {
        maxsecuritystrengths.put("sha-1", integers.valueof(128));

        maxsecuritystrengths.put("sha-224", integers.valueof(192));
        maxsecuritystrengths.put("sha-256", integers.valueof(256));
        maxsecuritystrengths.put("sha-384", integers.valueof(256));
        maxsecuritystrengths.put("sha-512", integers.valueof(256));

        maxsecuritystrengths.put("sha-512/224", integers.valueof(192));
        maxsecuritystrengths.put("sha-512/256", integers.valueof(256));
    }

    static int getmaxsecuritystrength(digest d)
    {
        return ((integer)maxsecuritystrengths.get(d.getalgorithmname())).intvalue();
    }

    static int getmaxsecuritystrength(mac m)
    {
        string name = m.getalgorithmname();

        return ((integer)maxsecuritystrengths.get(name.substring(0, name.indexof("/")))).intvalue();
    }

    /**
     * used by both dual ec and hash.
     */
    static byte[] hash_df(digest digest, byte[] seedmaterial, int seedlength)
    {
         // 1. temp = the null string.
        // 2. .
        // 3. counter = an 8-bit binary value representing the integer "1".
        // 4. for i = 1 to len do
        // comment : in step 4.1, no_of_bits_to_return
        // is used as a 32-bit string.
        // 4.1 temp = temp || hash (counter || no_of_bits_to_return ||
        // input_string).
        // 4.2 counter = counter + 1.
        // 5. requested_bits = leftmost (no_of_bits_to_return) of temp.
        // 6. return success and requested_bits.
        byte[] temp = new byte[(seedlength + 7) / 8];

        int len = temp.length / digest.getdigestsize();
        int counter = 1;

        byte[] dig = new byte[digest.getdigestsize()];

        for (int i = 0; i <= len; i++)
        {
            digest.update((byte)counter);

            digest.update((byte)(seedlength >> 24));
            digest.update((byte)(seedlength >> 16));
            digest.update((byte)(seedlength >> 8));
            digest.update((byte)seedlength);

            digest.update(seedmaterial, 0, seedmaterial.length);

            digest.dofinal(dig, 0);

            int bytestocopy = ((temp.length - i * dig.length) > dig.length)
                    ? dig.length
                    : (temp.length - i * dig.length);
            system.arraycopy(dig, 0, temp, i * dig.length, bytestocopy);

            counter++;
        }

        // do a left shift to get rid of excess bits.
        if (seedlength % 8 != 0)
        {
            int shift = 8 - (seedlength % 8);
            int carry = 0;

            for (int i = 0; i != temp.length; i++)
            {
                int b = temp[i] & 0xff;
                temp[i] = (byte)((b >>> shift) | (carry << (8 - shift)));
                carry = b;
            }
        }

        return temp;
    }

    static boolean istoolarge(byte[] bytes, int maxbytes)
    {
        return bytes != null && bytes.length > maxbytes;
    }
}
