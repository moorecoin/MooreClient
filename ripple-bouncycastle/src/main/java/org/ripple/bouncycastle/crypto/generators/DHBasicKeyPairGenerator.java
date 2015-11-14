package org.ripple.bouncycastle.crypto.generators;

import org.ripple.bouncycastle.crypto.asymmetriccipherkeypair;
import org.ripple.bouncycastle.crypto.asymmetriccipherkeypairgenerator;
import org.ripple.bouncycastle.crypto.keygenerationparameters;
import org.ripple.bouncycastle.crypto.params.dhkeygenerationparameters;
import org.ripple.bouncycastle.crypto.params.dhparameters;
import org.ripple.bouncycastle.crypto.params.dhprivatekeyparameters;
import org.ripple.bouncycastle.crypto.params.dhpublickeyparameters;

import java.math.biginteger;

/**
 * a basic diffie-hellman key pair generator.
 *
 * this generates keys consistent for use with the basic algorithm for
 * diffie-hellman.
 */
public class dhbasickeypairgenerator
    implements asymmetriccipherkeypairgenerator
{
    private dhkeygenerationparameters param;

    public void init(
        keygenerationparameters param)
    {
        this.param = (dhkeygenerationparameters)param;
    }

    public asymmetriccipherkeypair generatekeypair()
    {
        dhkeygeneratorhelper helper = dhkeygeneratorhelper.instance;
        dhparameters dhp = param.getparameters();

        biginteger x = helper.calculateprivate(dhp, param.getrandom()); 
        biginteger y = helper.calculatepublic(dhp, x);

        return new asymmetriccipherkeypair(
            new dhpublickeyparameters(y, dhp),
            new dhprivatekeyparameters(x, dhp));
    }
}
