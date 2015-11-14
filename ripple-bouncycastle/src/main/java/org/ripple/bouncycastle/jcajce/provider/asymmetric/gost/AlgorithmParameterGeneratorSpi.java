package org.ripple.bouncycastle.jcajce.provider.asymmetric.gost;

import java.security.algorithmparameters;
import java.security.invalidalgorithmparameterexception;
import java.security.securerandom;
import java.security.spec.algorithmparameterspec;

import org.ripple.bouncycastle.crypto.generators.gost3410parametersgenerator;
import org.ripple.bouncycastle.crypto.params.gost3410parameters;
import org.ripple.bouncycastle.jce.provider.bouncycastleprovider;
import org.ripple.bouncycastle.jce.spec.gost3410parameterspec;
import org.ripple.bouncycastle.jce.spec.gost3410publickeyparametersetspec;

public abstract class algorithmparametergeneratorspi
    extends java.security.algorithmparametergeneratorspi
{
    protected securerandom random;
    protected int strength = 1024;

    protected void engineinit(
        int strength,
        securerandom random)
    {
        this.strength = strength;
        this.random = random;
    }

    protected void engineinit(
        algorithmparameterspec genparamspec,
        securerandom random)
        throws invalidalgorithmparameterexception
    {
        throw new invalidalgorithmparameterexception("no supported algorithmparameterspec for gost3410 parameter generation.");
    }

    protected algorithmparameters enginegenerateparameters()
    {
        gost3410parametersgenerator pgen = new gost3410parametersgenerator();

        if (random != null)
        {
            pgen.init(strength, 2, random);
        }
        else
        {
            pgen.init(strength, 2, new securerandom());
        }

        gost3410parameters p = pgen.generateparameters();

        algorithmparameters params;

        try
        {
            params = algorithmparameters.getinstance("gost3410", bouncycastleprovider.provider_name);
            params.init(new gost3410parameterspec(new gost3410publickeyparametersetspec(p.getp(), p.getq(), p.geta())));
        }
        catch (exception e)
        {
            throw new runtimeexception(e.getmessage());
        }

        return params;
    }
}
