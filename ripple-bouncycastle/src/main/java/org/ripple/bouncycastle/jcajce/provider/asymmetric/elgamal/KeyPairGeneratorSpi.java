package org.ripple.bouncycastle.jcajce.provider.asymmetric.elgamal;

import java.security.invalidalgorithmparameterexception;
import java.security.keypair;
import java.security.securerandom;
import java.security.spec.algorithmparameterspec;

import javax.crypto.spec.dhparameterspec;

import org.ripple.bouncycastle.crypto.asymmetriccipherkeypair;
import org.ripple.bouncycastle.crypto.generators.elgamalkeypairgenerator;
import org.ripple.bouncycastle.crypto.generators.elgamalparametersgenerator;
import org.ripple.bouncycastle.crypto.params.elgamalkeygenerationparameters;
import org.ripple.bouncycastle.crypto.params.elgamalparameters;
import org.ripple.bouncycastle.crypto.params.elgamalprivatekeyparameters;
import org.ripple.bouncycastle.crypto.params.elgamalpublickeyparameters;
import org.ripple.bouncycastle.jce.provider.bouncycastleprovider;
import org.ripple.bouncycastle.jce.spec.elgamalparameterspec;

public class keypairgeneratorspi
    extends java.security.keypairgenerator
{
    elgamalkeygenerationparameters param;
    elgamalkeypairgenerator engine = new elgamalkeypairgenerator();
    int strength = 1024;
    int certainty = 20;
    securerandom random = new securerandom();
    boolean initialised = false;

    public keypairgeneratorspi()
    {
        super("elgamal");
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
        if (!(params instanceof elgamalparameterspec) && !(params instanceof dhparameterspec))
        {
            throw new invalidalgorithmparameterexception("parameter object not a dhparameterspec or an elgamalparameterspec");
        }

        if (params instanceof elgamalparameterspec)
        {
            elgamalparameterspec elparams = (elgamalparameterspec)params;

            param = new elgamalkeygenerationparameters(random, new elgamalparameters(elparams.getp(), elparams.getg()));
        }
        else
        {
            dhparameterspec dhparams = (dhparameterspec)params;

            param = new elgamalkeygenerationparameters(random, new elgamalparameters(dhparams.getp(), dhparams.getg(), dhparams.getl()));
        }

        engine.init(param);
        initialised = true;
    }

    public keypair generatekeypair()
    {
        if (!initialised)
        {
            dhparameterspec dhparams = bouncycastleprovider.configuration.getdhdefaultparameters(strength);

            if (dhparams != null)
            {
                param = new elgamalkeygenerationparameters(random, new elgamalparameters(dhparams.getp(), dhparams.getg(), dhparams.getl()));
            }
            else
            {
                elgamalparametersgenerator pgen = new elgamalparametersgenerator();

                pgen.init(strength, certainty, random);
                param = new elgamalkeygenerationparameters(random, pgen.generateparameters());
            }

            engine.init(param);
            initialised = true;
        }

        asymmetriccipherkeypair pair = engine.generatekeypair();
        elgamalpublickeyparameters pub = (elgamalpublickeyparameters)pair.getpublic();
        elgamalprivatekeyparameters priv = (elgamalprivatekeyparameters)pair.getprivate();

        return new keypair(new bcelgamalpublickey(pub),
            new bcelgamalprivatekey(priv));
    }
}

