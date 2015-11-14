package org.ripple.bouncycastle.crypto.generators;

import org.ripple.bouncycastle.crypto.cipherkeygenerator;
import org.ripple.bouncycastle.crypto.keygenerationparameters;
import org.ripple.bouncycastle.crypto.params.desparameters;

public class deskeygenerator
    extends cipherkeygenerator
{
    /**
     * initialise the key generator - if strength is set to zero
     * the key generated will be 64 bits in size, otherwise
     * strength can be 64 or 56 bits (if you don't count the parity bits).
     *
     * @param param the parameters to be used for key generation
     */
    public void init(
        keygenerationparameters param)
    {
        super.init(param);

        if (strength == 0 || strength == (56 / 8))
        {
            strength = desparameters.des_key_length;
        }
        else if (strength != desparameters.des_key_length)
        {
            throw new illegalargumentexception("des key must be "
                    + (desparameters.des_key_length * 8)
                    + " bits long.");
        }
    }

    public byte[] generatekey()
    {
        byte[]  newkey = new byte[desparameters.des_key_length];

        do
        {
            random.nextbytes(newkey);

            desparameters.setoddparity(newkey);
        }
        while (desparameters.isweakkey(newkey, 0));

        return newkey;
    }
}
