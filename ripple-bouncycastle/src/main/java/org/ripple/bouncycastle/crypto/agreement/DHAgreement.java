package org.ripple.bouncycastle.crypto.agreement;

import java.math.biginteger;
import java.security.securerandom;

import org.ripple.bouncycastle.crypto.asymmetriccipherkeypair;
import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.generators.dhkeypairgenerator;
import org.ripple.bouncycastle.crypto.params.asymmetrickeyparameter;
import org.ripple.bouncycastle.crypto.params.dhkeygenerationparameters;
import org.ripple.bouncycastle.crypto.params.dhparameters;
import org.ripple.bouncycastle.crypto.params.dhprivatekeyparameters;
import org.ripple.bouncycastle.crypto.params.dhpublickeyparameters;
import org.ripple.bouncycastle.crypto.params.parameterswithrandom;

/**
 * a diffie-hellman key exchange engine.
 * <p>
 * note: this uses mti/a0 key agreement in order to make the key agreement
 * secure against passive attacks. if you're doing diffie-hellman and both
 * parties have long term public keys you should look at using this. for
 * further information have a look at rfc 2631.
 * <p>
 * it's possible to extend this to more than two parties as well, for the moment
 * that is left as an exercise for the reader.
 */
public class dhagreement
{
    private dhprivatekeyparameters  key;
    private dhparameters            dhparams;
    private biginteger              privatevalue;
    private securerandom            random;

    public void init(
        cipherparameters    param)
    {
        asymmetrickeyparameter  kparam;

        if (param instanceof parameterswithrandom)
        {
            parameterswithrandom    rparam = (parameterswithrandom)param;

            this.random = rparam.getrandom();
            kparam = (asymmetrickeyparameter)rparam.getparameters();
        }
        else
        {
            this.random = new securerandom();
            kparam = (asymmetrickeyparameter)param;
        }

        
        if (!(kparam instanceof dhprivatekeyparameters))
        {
            throw new illegalargumentexception("dhengine expects dhprivatekeyparameters");
        }

        this.key = (dhprivatekeyparameters)kparam;
        this.dhparams = key.getparameters();
    }

    /**
     * calculate our initial message.
     */
    public biginteger calculatemessage()
    {
        dhkeypairgenerator dhgen = new dhkeypairgenerator();
        dhgen.init(new dhkeygenerationparameters(random, dhparams));
        asymmetriccipherkeypair dhpair = dhgen.generatekeypair();

        this.privatevalue = ((dhprivatekeyparameters)dhpair.getprivate()).getx();

        return ((dhpublickeyparameters)dhpair.getpublic()).gety();
    }

    /**
     * given a message from a given party and the corresponding public key,
     * calculate the next message in the agreement sequence. in this case
     * this will represent the shared secret.
     */
    public biginteger calculateagreement(
        dhpublickeyparameters   pub,
        biginteger              message)
    {
        if (!pub.getparameters().equals(dhparams))
        {
            throw new illegalargumentexception("diffie-hellman public key has wrong parameters.");
        }

        biginteger p = dhparams.getp();

        return message.modpow(key.getx(), p).multiply(pub.gety().modpow(privatevalue, p)).mod(p);
    }
}
