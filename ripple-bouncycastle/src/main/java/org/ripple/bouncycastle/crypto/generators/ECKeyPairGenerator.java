package org.ripple.bouncycastle.crypto.generators;

import java.math.biginteger;
import java.security.securerandom;

import org.ripple.bouncycastle.crypto.asymmetriccipherkeypair;
import org.ripple.bouncycastle.crypto.asymmetriccipherkeypairgenerator;
import org.ripple.bouncycastle.crypto.keygenerationparameters;
import org.ripple.bouncycastle.crypto.params.ecdomainparameters;
import org.ripple.bouncycastle.crypto.params.eckeygenerationparameters;
import org.ripple.bouncycastle.crypto.params.ecprivatekeyparameters;
import org.ripple.bouncycastle.crypto.params.ecpublickeyparameters;
import org.ripple.bouncycastle.math.ec.ecconstants;
import org.ripple.bouncycastle.math.ec.ecpoint;

public class eckeypairgenerator
    implements asymmetriccipherkeypairgenerator, ecconstants
{
    ecdomainparameters  params;
    securerandom        random;

    public void init(
        keygenerationparameters param)
    {
        eckeygenerationparameters  ecp = (eckeygenerationparameters)param;

        this.random = ecp.getrandom();
        this.params = ecp.getdomainparameters();
    }

    /**
     * given the domain parameters this routine generates an ec key
     * pair in accordance with x9.62 section 5.2.1 pages 26, 27.
     */
    public asymmetriccipherkeypair generatekeypair()
    {
        biginteger n = params.getn();
        int        nbitlength = n.bitlength();
        biginteger d;

        do
        {
            d = new biginteger(nbitlength, random);
        }
        while (d.equals(zero)  || (d.compareto(n) >= 0));

        ecpoint q = params.getg().multiply(d);

        return new asymmetriccipherkeypair(
            new ecpublickeyparameters(q, params),
            new ecprivatekeyparameters(d, params));
    }
}
