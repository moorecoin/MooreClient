package org.ripple.bouncycastle.jcajce.provider.asymmetric.rsa;

import java.math.biginteger;
import java.security.invalidalgorithmparameterexception;
import java.security.keypair;
import java.security.securerandom;
import java.security.spec.algorithmparameterspec;
import java.security.spec.rsakeygenparameterspec;

import org.ripple.bouncycastle.crypto.asymmetriccipherkeypair;
import org.ripple.bouncycastle.crypto.generators.rsakeypairgenerator;
import org.ripple.bouncycastle.crypto.params.rsakeygenerationparameters;
import org.ripple.bouncycastle.crypto.params.rsakeyparameters;
import org.ripple.bouncycastle.crypto.params.rsaprivatecrtkeyparameters;

public class keypairgeneratorspi
    extends java.security.keypairgenerator
{
    public keypairgeneratorspi(
        string algorithmname)
    {
        super(algorithmname);
    }

    final static biginteger defaultpublicexponent = biginteger.valueof(0x10001);
    final static int defaulttests = 12;

    rsakeygenerationparameters param;
    rsakeypairgenerator engine;

    public keypairgeneratorspi()
    {
        super("rsa");

        engine = new rsakeypairgenerator();
        param = new rsakeygenerationparameters(defaultpublicexponent,
            new securerandom(), 2048, defaulttests);
        engine.init(param);
    }

    public void initialize(
        int strength,
        securerandom random)
    {
        param = new rsakeygenerationparameters(defaultpublicexponent,
            random, strength, defaulttests);

        engine.init(param);
    }

    public void initialize(
        algorithmparameterspec params,
        securerandom random)
        throws invalidalgorithmparameterexception
    {
        if (!(params instanceof rsakeygenparameterspec))
        {
            throw new invalidalgorithmparameterexception("parameter object not a rsakeygenparameterspec");
        }
        rsakeygenparameterspec rsaparams = (rsakeygenparameterspec)params;

        param = new rsakeygenerationparameters(
            rsaparams.getpublicexponent(),
            random, rsaparams.getkeysize(), defaulttests);

        engine.init(param);
    }

    public keypair generatekeypair()
    {
        asymmetriccipherkeypair pair = engine.generatekeypair();
        rsakeyparameters pub = (rsakeyparameters)pair.getpublic();
        rsaprivatecrtkeyparameters priv = (rsaprivatecrtkeyparameters)pair.getprivate();

        return new keypair(new bcrsapublickey(pub),
            new bcrsaprivatecrtkey(priv));
    }
}
