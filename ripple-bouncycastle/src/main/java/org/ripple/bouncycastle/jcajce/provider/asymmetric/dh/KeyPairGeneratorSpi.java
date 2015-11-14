package org.ripple.bouncycastle.jcajce.provider.asymmetric.dh;

import java.security.invalidalgorithmparameterexception;
import java.security.keypair;
import java.security.securerandom;
import java.security.spec.algorithmparameterspec;
import java.util.hashtable;

import javax.crypto.spec.dhparameterspec;

import org.ripple.bouncycastle.crypto.asymmetriccipherkeypair;
import org.ripple.bouncycastle.crypto.generators.dhbasickeypairgenerator;
import org.ripple.bouncycastle.crypto.generators.dhparametersgenerator;
import org.ripple.bouncycastle.crypto.params.dhkeygenerationparameters;
import org.ripple.bouncycastle.crypto.params.dhparameters;
import org.ripple.bouncycastle.crypto.params.dhprivatekeyparameters;
import org.ripple.bouncycastle.crypto.params.dhpublickeyparameters;
import org.ripple.bouncycastle.jce.provider.bouncycastleprovider;
import org.ripple.bouncycastle.util.integers;

public class keypairgeneratorspi
    extends java.security.keypairgenerator
{
    private static hashtable params = new hashtable();
    private static object    lock = new object();

    dhkeygenerationparameters param;
    dhbasickeypairgenerator engine = new dhbasickeypairgenerator();
    int strength = 1024;
    int certainty = 20;
    securerandom random = new securerandom();
    boolean initialised = false;

    public keypairgeneratorspi()
    {
        super("dh");
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
        if (!(params instanceof dhparameterspec))
        {
            throw new invalidalgorithmparameterexception("parameter object not a dhparameterspec");
        }
        dhparameterspec dhparams = (dhparameterspec)params;

        param = new dhkeygenerationparameters(random, new dhparameters(dhparams.getp(), dhparams.getg(), null, dhparams.getl()));

        engine.init(param);
        initialised = true;
    }

    public keypair generatekeypair()
    {
        if (!initialised)
        {
            integer paramstrength = integers.valueof(strength);

            if (params.containskey(paramstrength))
            {
                param = (dhkeygenerationparameters)params.get(paramstrength);
            }
            else
            {
                dhparameterspec dhparams = bouncycastleprovider.configuration.getdhdefaultparameters(strength);

                if (dhparams != null)
                {
                    param = new dhkeygenerationparameters(random, new dhparameters(dhparams.getp(), dhparams.getg(), null, dhparams.getl()));
                }
                else
                {
                    synchronized (lock)
                    {
                        // we do the check again in case we were blocked by a generator for
                        // our key size.
                        if (params.containskey(paramstrength))
                        {
                            param = (dhkeygenerationparameters)params.get(paramstrength);
                        }
                        else
                        {

                            dhparametersgenerator pgen = new dhparametersgenerator();

                            pgen.init(strength, certainty, random);

                            param = new dhkeygenerationparameters(random, pgen.generateparameters());

                            params.put(paramstrength, param);
                        }
                    }
                }
            }

            engine.init(param);

            initialised = true;
        }

        asymmetriccipherkeypair pair = engine.generatekeypair();
        dhpublickeyparameters pub = (dhpublickeyparameters)pair.getpublic();
        dhprivatekeyparameters priv = (dhprivatekeyparameters)pair.getprivate();

        return new keypair(new bcdhpublickey(pub),
            new bcdhprivatekey(priv));
    }
}
