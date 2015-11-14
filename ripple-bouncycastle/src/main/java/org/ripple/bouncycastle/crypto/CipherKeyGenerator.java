package org.ripple.bouncycastle.crypto;

import java.security.securerandom;

/**
 * the base class for symmetric, or secret, cipher key generators.
 */
public class cipherkeygenerator
{
    protected securerandom  random;
    protected int           strength;

    /**
     * initialise the key generator.
     *
     * @param param the parameters to be used for key generation
     */
    public void init(
        keygenerationparameters param)
    {
        this.random = param.getrandom();
        this.strength = (param.getstrength() + 7) / 8;
    }

    /**
     * generate a secret key.
     *
     * @return a byte array containing the key value.
     */
    public byte[] generatekey()
    {
        byte[]  key = new byte[strength];

        random.nextbytes(key);

        return key;
    }
}
