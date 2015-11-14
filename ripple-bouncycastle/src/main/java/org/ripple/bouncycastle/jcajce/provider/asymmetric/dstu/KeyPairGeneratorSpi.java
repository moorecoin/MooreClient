package org.ripple.bouncycastle.jcajce.provider.asymmetric.dstu;

import java.math.biginteger;
import java.security.invalidalgorithmparameterexception;
import java.security.invalidparameterexception;
import java.security.keypair;
import java.security.securerandom;
import java.security.spec.algorithmparameterspec;
import java.security.spec.ecgenparameterspec;

import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.ua.dstu4145namedcurves;
import org.ripple.bouncycastle.crypto.asymmetriccipherkeypair;
import org.ripple.bouncycastle.crypto.generators.dstu4145keypairgenerator;
import org.ripple.bouncycastle.crypto.generators.eckeypairgenerator;
import org.ripple.bouncycastle.crypto.params.ecdomainparameters;
import org.ripple.bouncycastle.crypto.params.eckeygenerationparameters;
import org.ripple.bouncycastle.crypto.params.ecprivatekeyparameters;
import org.ripple.bouncycastle.crypto.params.ecpublickeyparameters;
import org.ripple.bouncycastle.jcajce.provider.asymmetric.util.ec5util;
import org.ripple.bouncycastle.jce.provider.bouncycastleprovider;
import org.ripple.bouncycastle.jce.spec.ecnamedcurvegenparameterspec;
import org.ripple.bouncycastle.jce.spec.ecnamedcurvespec;
import org.ripple.bouncycastle.jce.spec.ecparameterspec;
import org.ripple.bouncycastle.math.ec.eccurve;
import org.ripple.bouncycastle.math.ec.ecpoint;

public class keypairgeneratorspi
    extends java.security.keypairgenerator
{
    object ecparams = null;
    eckeypairgenerator engine = new dstu4145keypairgenerator();

    string algorithm = "dstu4145";
    eckeygenerationparameters param;
    //int strength = 239;
    securerandom random = null;
    boolean initialised = false;

    public keypairgeneratorspi()
    {
        super("dstu4145");
    }

    public void initialize(
        int strength,
        securerandom random)
    {
        this.random = random;

        if (ecparams != null)
        {
            try
            {
                initialize((ecgenparameterspec)ecparams, random);
            }
            catch (invalidalgorithmparameterexception e)
            {
                throw new invalidparameterexception("key size not configurable.");
            }
        }
        else
        {
            throw new invalidparameterexception("unknown key size.");
        }
    }

    public void initialize(
        algorithmparameterspec params,
        securerandom random)
        throws invalidalgorithmparameterexception
    {
        if (params instanceof ecparameterspec)
        {
            ecparameterspec p = (ecparameterspec)params;
            this.ecparams = params;

            param = new eckeygenerationparameters(new ecdomainparameters(p.getcurve(), p.getg(), p.getn()), random);

            engine.init(param);
            initialised = true;
        }
        else if (params instanceof java.security.spec.ecparameterspec)
        {
            java.security.spec.ecparameterspec p = (java.security.spec.ecparameterspec)params;
            this.ecparams = params;

            eccurve curve = ec5util.convertcurve(p.getcurve());
            ecpoint g = ec5util.convertpoint(curve, p.getgenerator(), false);

            param = new eckeygenerationparameters(new ecdomainparameters(curve, g, p.getorder(), biginteger.valueof(p.getcofactor())), random);

            engine.init(param);
            initialised = true;
        }
        else if (params instanceof ecgenparameterspec || params instanceof ecnamedcurvegenparameterspec)
        {
            string curvename;

            if (params instanceof ecgenparameterspec)
            {
                curvename = ((ecgenparameterspec)params).getname();
            }
            else
            {
                curvename = ((ecnamedcurvegenparameterspec)params).getname();
            }

            //ecdomainparameters ecp = ecgost3410namedcurves.getbyname(curvename);
            ecdomainparameters ecp = dstu4145namedcurves.getbyoid(new asn1objectidentifier(curvename));
            if (ecp == null)
            {
                throw new invalidalgorithmparameterexception("unknown curve name: " + curvename);
            }

            this.ecparams = new ecnamedcurvespec(
                curvename,
                ecp.getcurve(),
                ecp.getg(),
                ecp.getn(),
                ecp.geth(),
                ecp.getseed());

            java.security.spec.ecparameterspec p = (java.security.spec.ecparameterspec)ecparams;

            eccurve curve = ec5util.convertcurve(p.getcurve());
            ecpoint g = ec5util.convertpoint(curve, p.getgenerator(), false);

            param = new eckeygenerationparameters(new ecdomainparameters(curve, g, p.getorder(), biginteger.valueof(p.getcofactor())), random);

            engine.init(param);
            initialised = true;
        }
        else if (params == null && bouncycastleprovider.configuration.getecimplicitlyca() != null)
        {
            ecparameterspec p = bouncycastleprovider.configuration.getecimplicitlyca();
            this.ecparams = params;

            param = new eckeygenerationparameters(new ecdomainparameters(p.getcurve(), p.getg(), p.getn()), random);

            engine.init(param);
            initialised = true;
        }
        else if (params == null && bouncycastleprovider.configuration.getecimplicitlyca() == null)
        {
            throw new invalidalgorithmparameterexception("null parameter passed but no implicitca set");
        }
        else
        {
            throw new invalidalgorithmparameterexception("parameter object not a ecparameterspec: " + params.getclass().getname());
        }
    }

    public keypair generatekeypair()
    {
        if (!initialised)
        {
            throw new illegalstateexception("dstu key pair generator not initialised");
        }

        asymmetriccipherkeypair pair = engine.generatekeypair();
        ecpublickeyparameters pub = (ecpublickeyparameters)pair.getpublic();
        ecprivatekeyparameters priv = (ecprivatekeyparameters)pair.getprivate();

        if (ecparams instanceof ecparameterspec)
        {
            ecparameterspec p = (ecparameterspec)ecparams;

            bcdstu4145publickey pubkey = new bcdstu4145publickey(algorithm, pub, p);
            return new keypair(pubkey,
                new bcdstu4145privatekey(algorithm, priv, pubkey, p));
        }
        else if (ecparams == null)
        {
            return new keypair(new bcdstu4145publickey(algorithm, pub),
                new bcdstu4145privatekey(algorithm, priv));
        }
        else
        {
            java.security.spec.ecparameterspec p = (java.security.spec.ecparameterspec)ecparams;

            bcdstu4145publickey pubkey = new bcdstu4145publickey(algorithm, pub, p);

            return new keypair(pubkey, new bcdstu4145privatekey(algorithm, priv, pubkey, p));
        }
    }
}

