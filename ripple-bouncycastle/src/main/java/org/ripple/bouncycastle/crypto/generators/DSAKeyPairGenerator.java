package org.ripple.bouncycastle.crypto.generators;

import org.ripple.bouncycastle.crypto.asymmetriccipherkeypair;
import org.ripple.bouncycastle.crypto.asymmetriccipherkeypairgenerator;
import org.ripple.bouncycastle.crypto.keygenerationparameters;
import org.ripple.bouncycastle.crypto.params.dsakeygenerationparameters;
import org.ripple.bouncycastle.crypto.params.dsaparameters;
import org.ripple.bouncycastle.crypto.params.dsaprivatekeyparameters;
import org.ripple.bouncycastle.crypto.params.dsapublickeyparameters;
import org.ripple.bouncycastle.util.bigintegers;

import java.math.biginteger;
import java.security.securerandom;

/**
 * a dsa key pair generator.
 *
 * this generates dsa keys in line with the method described 
 * in <i>fips 186-3 b.1 ffc key pair generation</i>.
 */
public class dsakeypairgenerator
    implements asymmetriccipherkeypairgenerator
{
    private static final biginteger one = biginteger.valueof(1);

    private dsakeygenerationparameters param;

    public void init(
        keygenerationparameters param)
    {
        this.param = (dsakeygenerationparameters)param;
    }

    public asymmetriccipherkeypair generatekeypair()
    {
        dsaparameters dsaparams = param.getparameters();

        biginteger x = generateprivatekey(dsaparams.getq(), param.getrandom());
        biginteger y = calculatepublickey(dsaparams.getp(), dsaparams.getg(), x);

        return new asymmetriccipherkeypair(
            new dsapublickeyparameters(y, dsaparams),
            new dsaprivatekeyparameters(x, dsaparams));
    }

    private static biginteger generateprivatekey(biginteger q, securerandom random)
    {
        // todo prefer this method? (change test cases that used fixed random)
        // b.1.1 key pair generation using extra random bits
//        biginteger c = new biginteger(q.bitlength() + 64, random);
//        return c.mod(q.subtract(one)).add(one);

        // b.1.2 key pair generation by testing candidates
        return bigintegers.createrandominrange(one, q.subtract(one), random);
    }

    private static biginteger calculatepublickey(biginteger p, biginteger g, biginteger x)
    {
        return g.modpow(x, p);
    }
}
