package org.ripple.bouncycastle.crypto.ec;

import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.params.ecprivatekeyparameters;
import org.ripple.bouncycastle.math.ec.ecpoint;

/**
 * this does your basic decryption elgamal style using ec
 */
public class ecelgamaldecryptor
    implements ecdecryptor
{
    private ecprivatekeyparameters key;

    /**
     * initialise the decryptor.
     *
     * @param param the necessary ec key parameters.
     */
    public void init(
        cipherparameters param)
    {
        if (!(param instanceof ecprivatekeyparameters))
        {
            throw new illegalargumentexception("ecprivatekeyparameters are required for decryption.");
        }

        this.key = (ecprivatekeyparameters)param;
    }

    /**
     * decrypt an ec pair producing the original ec point.
     *
     * @param pair the ec point pair to process.
     * @return the result of the elgamal process.
     */
    public ecpoint decrypt(ecpair pair)
    {
        if (key == null)
        {
            throw new illegalstateexception("ecelgamaldecryptor not initialised");
        }

        ecpoint tmp = pair.getx().multiply(key.getd());

        return pair.gety().add(tmp.negate());
    }
}
