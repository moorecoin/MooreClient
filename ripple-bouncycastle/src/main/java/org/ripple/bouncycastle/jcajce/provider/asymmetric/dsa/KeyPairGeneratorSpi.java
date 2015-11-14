package org.ripple.bouncycastle.jcajce.provider.asymmetric.dsa;

import java.security.invalidalgorithmparameterexception;
import java.security.invalidparameterexception;
import java.security.keypair;
import java.security.securerandom;
import java.security.spec.algorithmparameterspec;
import java.security.spec.dsaparameterspec;

import org.ripple.bouncycastle.crypto.asymmetriccipherkeypair;
import org.ripple.bouncycastle.crypto.generators.dsakeypairgenerator;
import org.ripple.bouncycastle.crypto.generators.dsaparametersgenerator;
import org.ripple.bouncycastle.crypto.params.dsakeygenerationparameters;
import org.ripple.bouncycastle.crypto.params.dsaparameters;
import org.ripple.bouncycastle.crypto.params.dsaprivatekeyparameters;
import org.ripple.bouncycastle.crypto.params.dsapublickeyparameters;

public class keypairgeneratorspi
    extends java.security.keypairgenerator
{
    dsakeygenerationparameters param;
    dsakeypairgenerator engine = new dsakeypairgenerator();
    int strength = 1024;
    int certainty = 20;
    securerandom random = new securerandom();
    boolean initialised = false;

    public keypairgeneratorspi()
    {
        super("dsa");
    }

    public void initialize(
        int strength,
        securerandom random)
    {
        if (strength < 512 || strength > 1024 || strength % 64 != 0)
        {
            throw new invalidparameterexception("strength must be from 512 - 1024 and a multiple of 64");
        }

        this.strength = strength;
        this.random = random;
    }

    public void initialize(
        algorithmparameterspec params,
        securerandom random)
        throws invalidalgorithmparameterexception
    {
        if (!(params instanceof dsaparameterspec))
        {
            throw new invalidalgorithmparameterexception("parameter object not a dsaparameterspec");
        }
        dsaparameterspec dsaparams = (dsaparameterspec)params;

        param = new dsakeygenerationparameters(random, new dsaparameters(dsaparams.getp(), dsaparams.getq(), dsaparams.getg()));

        engine.init(param);
        initialised = true;
    }

    public keypair generatekeypair()
    {
        if (!initialised)
        {
            dsaparametersgenerator pgen = new dsaparametersgenerator();

            pgen.init(strength, certainty, random);
            param = new dsakeygenerationparameters(random, pgen.generateparameters());
            engine.init(param);
            initialised = true;
        }

        asymmetriccipherkeypair pair = engine.generatekeypair();
        dsapublickeyparameters pub = (dsapublickeyparameters)pair.getpublic();
        dsaprivatekeyparameters priv = (dsaprivatekeyparameters)pair.getprivate();

        return new keypair(new bcdsapublickey(pub),
            new bcdsaprivatekey(priv));
    }
}
