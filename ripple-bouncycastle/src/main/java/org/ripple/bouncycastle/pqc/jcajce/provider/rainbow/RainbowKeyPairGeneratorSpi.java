package org.ripple.bouncycastle.pqc.jcajce.provider.rainbow;

import java.security.invalidalgorithmparameterexception;
import java.security.keypair;
import java.security.securerandom;
import java.security.spec.algorithmparameterspec;

import org.ripple.bouncycastle.crypto.asymmetriccipherkeypair;
import org.ripple.bouncycastle.pqc.crypto.rainbow.rainbowkeygenerationparameters;
import org.ripple.bouncycastle.pqc.crypto.rainbow.rainbowkeypairgenerator;
import org.ripple.bouncycastle.pqc.crypto.rainbow.rainbowparameters;
import org.ripple.bouncycastle.pqc.crypto.rainbow.rainbowprivatekeyparameters;
import org.ripple.bouncycastle.pqc.crypto.rainbow.rainbowpublickeyparameters;
import org.ripple.bouncycastle.pqc.jcajce.spec.rainbowparameterspec;

public class rainbowkeypairgeneratorspi
    extends java.security.keypairgenerator
{
    rainbowkeygenerationparameters param;
    rainbowkeypairgenerator engine = new rainbowkeypairgenerator();
    int strength = 1024;
    securerandom random = new securerandom();
    boolean initialised = false;

    public rainbowkeypairgeneratorspi()
    {
        super("rainbow");
    }

    public void initialize(
        int strength,
        securerandom random)
    {
        this.strength = strength;
        this.random = random;
    }

    public void initialize(
        algorithmparameterspec params,
        securerandom random)
        throws invalidalgorithmparameterexception
    {
        if (!(params instanceof rainbowparameterspec))
        {
            throw new invalidalgorithmparameterexception("parameter object not a rainbowparameterspec");
        }
        rainbowparameterspec rainbowparams = (rainbowparameterspec)params;

        param = new rainbowkeygenerationparameters(random, new rainbowparameters(rainbowparams.getvi()));

        engine.init(param);
        initialised = true;
    }

    public keypair generatekeypair()
    {
        if (!initialised)
        {
            param = new rainbowkeygenerationparameters(random, new rainbowparameters(new rainbowparameterspec().getvi()));

            engine.init(param);
            initialised = true;
        }

        asymmetriccipherkeypair pair = engine.generatekeypair();
        rainbowpublickeyparameters pub = (rainbowpublickeyparameters)pair.getpublic();
        rainbowprivatekeyparameters priv = (rainbowprivatekeyparameters)pair.getprivate();

        return new keypair(new bcrainbowpublickey(pub),
            new bcrainbowprivatekey(priv));
    }
}
