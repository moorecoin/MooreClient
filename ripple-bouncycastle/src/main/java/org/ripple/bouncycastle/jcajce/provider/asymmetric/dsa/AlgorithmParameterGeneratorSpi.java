package org.ripple.bouncycastle.jcajce.provider.asymmetric.dsa;

import java.security.algorithmparameters;
import java.security.invalidalgorithmparameterexception;
import java.security.invalidparameterexception;
import java.security.securerandom;
import java.security.spec.algorithmparameterspec;
import java.security.spec.dsaparameterspec;

import org.ripple.bouncycastle.crypto.digests.sha256digest;
import org.ripple.bouncycastle.crypto.generators.dsaparametersgenerator;
import org.ripple.bouncycastle.crypto.params.dsaparametergenerationparameters;
import org.ripple.bouncycastle.crypto.params.dsaparameters;
import org.ripple.bouncycastle.jce.provider.bouncycastleprovider;

public class algorithmparametergeneratorspi
    extends java.security.algorithmparametergeneratorspi
{
    protected securerandom random;
    protected int strength = 1024;
    protected dsaparametergenerationparameters params;

    protected void engineinit(
        int strength,
        securerandom random)
    {
        if (strength < 512 || strength > 3072)
        {
            throw new invalidparameterexception("strength must be from 512 - 3072");
        }

        if (strength <= 1024 && strength % 64 != 0)
        {
            throw new invalidparameterexception("strength must be a multiple of 64 below 1024 bits.");
        }

        if (strength > 1024 && strength % 1024 != 0)
        {
            throw new invalidparameterexception("strength must be a multiple of 1024 above 1024 bits.");
        }

        this.strength = strength;
        this.random = random;
    }

    protected void engineinit(
        algorithmparameterspec genparamspec,
        securerandom random)
        throws invalidalgorithmparameterexception
    {
        throw new invalidalgorithmparameterexception("no supported algorithmparameterspec for dsa parameter generation.");
    }

    protected algorithmparameters enginegenerateparameters()
    {
        dsaparametersgenerator pgen;

        if (strength <= 1024)
        {
            pgen = new dsaparametersgenerator();
        }
        else
        {
            pgen = new dsaparametersgenerator(new sha256digest());
        }

        if (random == null)
        {
            random = new securerandom();
        }

        if (strength == 1024)
        {
            params = new dsaparametergenerationparameters(1024, 160, 80, random);
            pgen.init(params);
        }
        else if (strength > 1024)
        {
            params = new dsaparametergenerationparameters(strength, 256, 80, random);
            pgen.init(params);
        }
        else
        {
            pgen.init(strength, 20, random);
        }

        dsaparameters p = pgen.generateparameters();

        algorithmparameters params;

        try
        {
            params = algorithmparameters.getinstance("dsa", bouncycastleprovider.provider_name);
            params.init(new dsaparameterspec(p.getp(), p.getq(), p.getg()));
        }
        catch (exception e)
        {
            throw new runtimeexception(e.getmessage());
        }

        return params;
    }
}
