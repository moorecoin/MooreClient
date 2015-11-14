package org.ripple.bouncycastle.jcajce.provider.asymmetric.dh;

import java.security.algorithmparameters;
import java.security.invalidalgorithmparameterexception;
import java.security.securerandom;
import java.security.spec.algorithmparameterspec;

import javax.crypto.spec.dhgenparameterspec;
import javax.crypto.spec.dhparameterspec;

import org.ripple.bouncycastle.crypto.generators.dhparametersgenerator;
import org.ripple.bouncycastle.crypto.params.dhparameters;
import org.ripple.bouncycastle.jce.provider.bouncycastleprovider;

public class algorithmparametergeneratorspi
    extends java.security.algorithmparametergeneratorspi
{
    protected securerandom random;
    protected int strength = 1024;

    private int l = 0;

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
        if (!(genparamspec instanceof dhgenparameterspec))
        {
            throw new invalidalgorithmparameterexception("dh parameter generator requires a dhgenparameterspec for initialisation");
        }
        dhgenparameterspec spec = (dhgenparameterspec)genparamspec;

        this.strength = spec.getprimesize();
        this.l = spec.getexponentsize();
        this.random = random;
    }

    protected algorithmparameters enginegenerateparameters()
    {
        dhparametersgenerator pgen = new dhparametersgenerator();

        if (random != null)
        {
            pgen.init(strength, 20, random);
        }
        else
        {
            pgen.init(strength, 20, new securerandom());
        }

        dhparameters p = pgen.generateparameters();

        algorithmparameters params;

        try
        {
            params = algorithmparameters.getinstance("dh", bouncycastleprovider.provider_name);
            params.init(new dhparameterspec(p.getp(), p.getg(), l));
        }
        catch (exception e)
        {
            throw new runtimeexception(e.getmessage());
        }

        return params;
    }

}
