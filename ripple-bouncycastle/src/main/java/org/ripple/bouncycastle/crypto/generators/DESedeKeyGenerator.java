package org.ripple.bouncycastle.crypto.generators;

import org.ripple.bouncycastle.crypto.keygenerationparameters;
import org.ripple.bouncycastle.crypto.params.desedeparameters;

public class desedekeygenerator
    extends deskeygenerator
{
    /**
     * initialise the key generator - if strength is set to zero
     * the key generated will be 192 bits in size, otherwise
     * strength can be 128 or 192 (or 112 or 168 if you don't count
     * parity bits), depending on whether you wish to do 2-key or 3-key
     * triple des.
     *
     * @param param the parameters to be used for key generation
     */
    public void init(
        keygenerationparameters param)
    {
        this.random = param.getrandom();
        this.strength = (param.getstrength() + 7) / 8;

        if (strength == 0 || strength == (168 / 8))
        {
            strength = desedeparameters.des_ede_key_length;
        }
        else if (strength == (112 / 8))
        {
            strength = 2 * desedeparameters.des_key_length;
        }
        else if (strength != desedeparameters.des_ede_key_length
                && strength != (2 * desedeparameters.des_key_length))
        {
            throw new illegalargumentexception("desede key must be "
                + (desedeparameters.des_ede_key_length * 8) + " or "
                + (2 * 8 * desedeparameters.des_key_length)
                + " bits long.");
        }
    }

    public byte[] generatekey()
    {
        byte[]  newkey = new byte[strength];

        do
        {
            random.nextbytes(newkey);

            desedeparameters.setoddparity(newkey);
        }
        while (desedeparameters.isweakkey(newkey, 0, newkey.length));

        return newkey;
    }
}
