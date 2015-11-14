package org.ripple.bouncycastle.crypto.agreement;

import java.math.biginteger;

import org.ripple.bouncycastle.crypto.basicagreement;
import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.params.asymmetrickeyparameter;
import org.ripple.bouncycastle.crypto.params.dhparameters;
import org.ripple.bouncycastle.crypto.params.dhprivatekeyparameters;
import org.ripple.bouncycastle.crypto.params.dhpublickeyparameters;
import org.ripple.bouncycastle.crypto.params.parameterswithrandom;

/**
 * a diffie-hellman key agreement class.
 * <p>
 * note: this is only the basic algorithm, it doesn't take advantage of
 * long term public keys if they are available. see the dhagreement class
 * for a "better" implementation.
 */
public class dhbasicagreement
    implements basicagreement
{
    private dhprivatekeyparameters  key;
    private dhparameters            dhparams;

    public void init(
        cipherparameters    param)
    {
        asymmetrickeyparameter  kparam;

        if (param instanceof parameterswithrandom)
        {
            parameterswithrandom rparam = (parameterswithrandom)param;
            kparam = (asymmetrickeyparameter)rparam.getparameters();
        }
        else
        {
            kparam = (asymmetrickeyparameter)param;
        }

        if (!(kparam instanceof dhprivatekeyparameters))
        {
            throw new illegalargumentexception("dhengine expects dhprivatekeyparameters");
        }

        this.key = (dhprivatekeyparameters)kparam;
        this.dhparams = key.getparameters();
    }

    public int getfieldsize()
    {
        return (key.getparameters().getp().bitlength() + 7) / 8;
    }

    /**
     * given a short term public key from a given party calculate the next
     * message in the agreement sequence. 
     */
    public biginteger calculateagreement(
        cipherparameters   pubkey)
    {
        dhpublickeyparameters   pub = (dhpublickeyparameters)pubkey;

        if (!pub.getparameters().equals(dhparams))
        {
            throw new illegalargumentexception("diffie-hellman public key has wrong parameters.");
        }

        return pub.gety().modpow(key.getx(), dhparams.getp());
    }
}
