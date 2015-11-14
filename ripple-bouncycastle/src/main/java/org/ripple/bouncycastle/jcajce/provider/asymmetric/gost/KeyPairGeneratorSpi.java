package org.ripple.bouncycastle.jcajce.provider.asymmetric.gost;

import java.security.invalidalgorithmparameterexception;
import java.security.keypair;
import java.security.securerandom;
import java.security.spec.algorithmparameterspec;

import org.ripple.bouncycastle.asn1.cryptopro.cryptoproobjectidentifiers;
import org.ripple.bouncycastle.crypto.asymmetriccipherkeypair;
import org.ripple.bouncycastle.crypto.generators.gost3410keypairgenerator;
import org.ripple.bouncycastle.crypto.params.gost3410keygenerationparameters;
import org.ripple.bouncycastle.crypto.params.gost3410parameters;
import org.ripple.bouncycastle.crypto.params.gost3410privatekeyparameters;
import org.ripple.bouncycastle.crypto.params.gost3410publickeyparameters;
import org.ripple.bouncycastle.jce.spec.gost3410parameterspec;
import org.ripple.bouncycastle.jce.spec.gost3410publickeyparametersetspec;

public class keypairgeneratorspi
    extends java.security.keypairgenerator
{
    gost3410keygenerationparameters param;
    gost3410keypairgenerator engine = new gost3410keypairgenerator();
    gost3410parameterspec gost3410params;
    int strength = 1024;
    securerandom random = null;
    boolean initialised = false;

    public keypairgeneratorspi()
    {
        super("gost3410");
    }

    public void initialize(
        int strength,
        securerandom random)
    {
        this.strength = strength;
        this.random = random;
    }

    private void init(
        gost3410parameterspec gparams,
        securerandom random)
    {
        gost3410publickeyparametersetspec spec = gparams.getpublickeyparameters();

        param = new gost3410keygenerationparameters(random, new gost3410parameters(spec.getp(), spec.getq(), spec.geta()));

        engine.init(param);

        initialised = true;
        gost3410params = gparams;
    }

    public void initialize(
        algorithmparameterspec params,
        securerandom random)
        throws invalidalgorithmparameterexception
    {
        if (!(params instanceof gost3410parameterspec))
        {
            throw new invalidalgorithmparameterexception("parameter object not a gost3410parameterspec");
        }

        init((gost3410parameterspec)params, random);
    }

    public keypair generatekeypair()
    {
        if (!initialised)
        {
            init(new gost3410parameterspec(cryptoproobjectidentifiers.gostr3410_94_cryptopro_a.getid()), new securerandom());
        }

        asymmetriccipherkeypair pair = engine.generatekeypair();
        gost3410publickeyparameters pub = (gost3410publickeyparameters)pair.getpublic();
        gost3410privatekeyparameters priv = (gost3410privatekeyparameters)pair.getprivate();

        return new keypair(new bcgost3410publickey(pub, gost3410params), new bcgost3410privatekey(priv, gost3410params));
    }
}
