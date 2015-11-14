package org.ripple.bouncycastle.crypto.generators;

import java.math.biginteger;

import org.ripple.bouncycastle.crypto.asymmetriccipherkeypair;
import org.ripple.bouncycastle.crypto.asymmetriccipherkeypairgenerator;
import org.ripple.bouncycastle.crypto.keygenerationparameters;
import org.ripple.bouncycastle.crypto.params.dhparameters;
import org.ripple.bouncycastle.crypto.params.elgamalkeygenerationparameters;
import org.ripple.bouncycastle.crypto.params.elgamalparameters;
import org.ripple.bouncycastle.crypto.params.elgamalprivatekeyparameters;
import org.ripple.bouncycastle.crypto.params.elgamalpublickeyparameters;

/**
 * a elgamal key pair generator.
 * <p>
 * this generates keys consistent for use with elgamal as described in
 * page 164 of "handbook of applied cryptography".
 */
public class elgamalkeypairgenerator
    implements asymmetriccipherkeypairgenerator
{
    private elgamalkeygenerationparameters param;

    public void init(
        keygenerationparameters param)
    {
        this.param = (elgamalkeygenerationparameters)param;
    }

    public asymmetriccipherkeypair generatekeypair()
    {
        dhkeygeneratorhelper helper = dhkeygeneratorhelper.instance;
        elgamalparameters egp = param.getparameters();
        dhparameters dhp = new dhparameters(egp.getp(), egp.getg(), null, egp.getl());  

        biginteger x = helper.calculateprivate(dhp, param.getrandom()); 
        biginteger y = helper.calculatepublic(dhp, x);

        return new asymmetriccipherkeypair(
            new elgamalpublickeyparameters(y, egp),
            new elgamalprivatekeyparameters(x, egp));
    }
}
