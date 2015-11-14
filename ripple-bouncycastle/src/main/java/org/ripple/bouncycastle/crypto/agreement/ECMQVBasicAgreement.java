package org.ripple.bouncycastle.crypto.agreement;

import java.math.biginteger;

import org.ripple.bouncycastle.crypto.basicagreement;
import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.params.ecdomainparameters;
import org.ripple.bouncycastle.crypto.params.ecprivatekeyparameters;
import org.ripple.bouncycastle.crypto.params.ecpublickeyparameters;
import org.ripple.bouncycastle.crypto.params.mqvprivateparameters;
import org.ripple.bouncycastle.crypto.params.mqvpublicparameters;
import org.ripple.bouncycastle.math.ec.ecalgorithms;
import org.ripple.bouncycastle.math.ec.ecconstants;
import org.ripple.bouncycastle.math.ec.ecpoint;

public class ecmqvbasicagreement
    implements basicagreement
{
    mqvprivateparameters privparams;

    public void init(
        cipherparameters key)
    {
        this.privparams = (mqvprivateparameters)key;
    }

    public int getfieldsize()
    {
        return (privparams.getstaticprivatekey().getparameters().getcurve().getfieldsize() + 7) / 8;
    }

    public biginteger calculateagreement(cipherparameters pubkey)
    {
        mqvpublicparameters pubparams = (mqvpublicparameters)pubkey;

        ecprivatekeyparameters staticprivatekey = privparams.getstaticprivatekey();

        ecpoint agreement = calculatemqvagreement(staticprivatekey.getparameters(), staticprivatekey,
            privparams.getephemeralprivatekey(), privparams.getephemeralpublickey(),
            pubparams.getstaticpublickey(), pubparams.getephemeralpublickey());

        return agreement.getx().tobiginteger();
    }

    // the ecmqv primitive as described in sec-1, 3.4
    private ecpoint calculatemqvagreement(
        ecdomainparameters      parameters,
        ecprivatekeyparameters  d1u,
        ecprivatekeyparameters  d2u,
        ecpublickeyparameters   q2u,
        ecpublickeyparameters   q1v,
        ecpublickeyparameters   q2v)
    {
        biginteger n = parameters.getn();
        int e = (n.bitlength() + 1) / 2;
        biginteger powe = ecconstants.one.shiftleft(e);

        // the q2u public key is optional
        ecpoint q;
        if (q2u == null)
        {
            q = parameters.getg().multiply(d2u.getd());
        }
        else
        {
            q = q2u.getq();
        }

        biginteger x = q.getx().tobiginteger();
        biginteger xbar = x.mod(powe);
        biginteger q2ubar = xbar.setbit(e);
        biginteger s = d1u.getd().multiply(q2ubar).mod(n).add(d2u.getd()).mod(n);

        biginteger xprime = q2v.getq().getx().tobiginteger();
        biginteger xprimebar = xprime.mod(powe);
        biginteger q2vbar = xprimebar.setbit(e);

        biginteger hs = parameters.geth().multiply(s).mod(n);

//        ecpoint p = q1v.getq().multiply(q2vbar).add(q2v.getq()).multiply(hs);
        ecpoint p = ecalgorithms.sumoftwomultiplies(
            q1v.getq(), q2vbar.multiply(hs).mod(n), q2v.getq(), hs);

        if (p.isinfinity())
        {
            throw new illegalstateexception("infinity is not a valid agreement value for mqv");
        }

        return p;
    }
}
