package org.ripple.bouncycastle.openpgp.operator.bc;

import java.security.securerandom;

import org.ripple.bouncycastle.crypto.asymmetricblockcipher;
import org.ripple.bouncycastle.crypto.invalidciphertextexception;
import org.ripple.bouncycastle.crypto.params.asymmetrickeyparameter;
import org.ripple.bouncycastle.crypto.params.parameterswithrandom;
import org.ripple.bouncycastle.openpgp.pgpexception;
import org.ripple.bouncycastle.openpgp.pgppublickey;
import org.ripple.bouncycastle.openpgp.operator.publickeykeyencryptionmethodgenerator;

/**
 * a method generator for supporting public key based encryption operations.
 */
public class bcpublickeykeyencryptionmethodgenerator
    extends publickeykeyencryptionmethodgenerator
{
    private securerandom random;
    private bcpgpkeyconverter keyconverter = new bcpgpkeyconverter();

    /**
     * create a public key encryption method generator with the method to be based on the passed in key.
     *
     * @param key   the public key to use for encryption.
     */
    public bcpublickeykeyencryptionmethodgenerator(pgppublickey key)
    {
        super(key);
    }

    /**
     * provide a user defined source of randomness.
     *
     * @param random  the secure random to be used.
     * @return  the current generator.
     */
    public bcpublickeykeyencryptionmethodgenerator setsecurerandom(securerandom random)
    {
        this.random = random;

        return this;
    }

    protected byte[] encryptsessioninfo(pgppublickey pubkey, byte[] sessioninfo)
        throws pgpexception
    {
        try
        {
            asymmetricblockcipher c = bcimplprovider.createpublickeycipher(pubkey.getalgorithm());

            asymmetrickeyparameter key = keyconverter.getpublickey(pubkey);

            if (random == null)
            {
                random = new securerandom();
            }

            c.init(true, new parameterswithrandom(key, random));

            return c.processblock(sessioninfo, 0, sessioninfo.length);
        }
        catch (invalidciphertextexception e)
        {
            throw new pgpexception("exception encrypting session info: " + e.getmessage(), e);
        }
    }
}
