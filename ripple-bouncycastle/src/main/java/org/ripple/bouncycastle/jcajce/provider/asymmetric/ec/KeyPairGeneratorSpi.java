package org.ripple.bouncycastle.jcajce.provider.asymmetric.ec;

import java.math.biginteger;
import java.security.invalidalgorithmparameterexception;
import java.security.invalidparameterexception;
import java.security.keypair;
import java.security.securerandom;
import java.security.spec.algorithmparameterspec;
import java.security.spec.ecgenparameterspec;
import java.util.hashtable;

import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.nist.nistnamedcurves;
import org.ripple.bouncycastle.asn1.sec.secnamedcurves;
import org.ripple.bouncycastle.asn1.teletrust.teletrustnamedcurves;
import org.ripple.bouncycastle.asn1.x9.x962namedcurves;
import org.ripple.bouncycastle.asn1.x9.x9ecparameters;
import org.ripple.bouncycastle.crypto.asymmetriccipherkeypair;
import org.ripple.bouncycastle.crypto.generators.eckeypairgenerator;
import org.ripple.bouncycastle.crypto.params.ecdomainparameters;
import org.ripple.bouncycastle.crypto.params.eckeygenerationparameters;
import org.ripple.bouncycastle.crypto.params.ecprivatekeyparameters;
import org.ripple.bouncycastle.crypto.params.ecpublickeyparameters;
import org.ripple.bouncycastle.jcajce.provider.asymmetric.util.ec5util;
import org.ripple.bouncycastle.jcajce.provider.config.providerconfiguration;
import org.ripple.bouncycastle.jce.provider.bouncycastleprovider;
import org.ripple.bouncycastle.jce.spec.ecnamedcurvegenparameterspec;
import org.ripple.bouncycastle.jce.spec.ecnamedcurvespec;
import org.ripple.bouncycastle.jce.spec.ecparameterspec;
import org.ripple.bouncycastle.math.ec.eccurve;
import org.ripple.bouncycastle.math.ec.ecpoint;
import org.ripple.bouncycastle.util.integers;

public abstract class keypairgeneratorspi
    extends java.security.keypairgenerator
{
    public keypairgeneratorspi(string algorithmname)
    {
        super(algorithmname);
    }

    public static class ec
        extends keypairgeneratorspi
    {
        eckeygenerationparameters   param;
        eckeypairgenerator          engine = new eckeypairgenerator();
        object                      ecparams = null;
        int                         strength = 239;
        int                         certainty = 50;
        securerandom                random = new securerandom();
        boolean                     initialised = false;
        string                      algorithm;
        providerconfiguration       configuration;

        static private hashtable    ecparameters;

        static {
            ecparameters = new hashtable();

            ecparameters.put(integers.valueof(192), new ecgenparameterspec("prime192v1")); // a.k.a p-192
            ecparameters.put(integers.valueof(239), new ecgenparameterspec("prime239v1"));
            ecparameters.put(integers.valueof(256), new ecgenparameterspec("prime256v1")); // a.k.a p-256

            ecparameters.put(integers.valueof(224), new ecgenparameterspec("p-224"));
            ecparameters.put(integers.valueof(384), new ecgenparameterspec("p-384"));
            ecparameters.put(integers.valueof(521), new ecgenparameterspec("p-521"));
        }

        public ec()
        {
            super("ec");
            this.algorithm = "ec";
            this.configuration = bouncycastleprovider.configuration;
        }

        public ec(
            string  algorithm,
            providerconfiguration configuration)
        {
            super(algorithm);
            this.algorithm = algorithm;
            this.configuration = configuration;
        }

        public void initialize(
            int             strength,
            securerandom    random)
        {
            this.strength = strength;
            this.random = random;
            ecgenparameterspec ecparams = (ecgenparameterspec)ecparameters.get(integers.valueof(strength));

            if (ecparams != null)
            {
                try
                {
                    initialize(ecparams, random);
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
            algorithmparameterspec  params,
            securerandom            random)
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

                x9ecparameters  ecp = x962namedcurves.getbyname(curvename);
                if (ecp == null)
                {
                    ecp = secnamedcurves.getbyname(curvename);
                    if (ecp == null)
                    {
                        ecp = nistnamedcurves.getbyname(curvename);
                    }
                    if (ecp == null)
                    {
                        ecp = teletrustnamedcurves.getbyname(curvename);
                    }
                    if (ecp == null)
                    {
                        // see if it's actually an oid string (sunjsse serverhandshaker setupephemeralecdhkeys bug)
                        try
                        {
                            asn1objectidentifier oid = new asn1objectidentifier(curvename);
                            ecp = x962namedcurves.getbyoid(oid);
                            if (ecp == null)
                            {
                                ecp = secnamedcurves.getbyoid(oid);
                            }
                            if (ecp == null)
                            {
                                ecp = nistnamedcurves.getbyoid(oid);
                            }
                            if (ecp == null)
                            {
                                ecp = teletrustnamedcurves.getbyoid(oid);
                            }
                            if (ecp == null)
                            {
                                throw new invalidalgorithmparameterexception("unknown curve oid: " + curvename);
                            }
                        }
                        catch (illegalargumentexception ex)
                        {
                            throw new invalidalgorithmparameterexception("unknown curve name: " + curvename);
                        }
                    }
                }

                this.ecparams = new ecnamedcurvespec(
                            curvename,
                            ecp.getcurve(),
                            ecp.getg(),
                            ecp.getn(),
                            ecp.geth(),
                            null); // ecp.getseed());   work-around jdk bug -- it won't look up named curves properly if seed is present

                java.security.spec.ecparameterspec p = (java.security.spec.ecparameterspec)ecparams;

                eccurve curve = ec5util.convertcurve(p.getcurve());
                ecpoint g = ec5util.convertpoint(curve, p.getgenerator(), false);

                param = new eckeygenerationparameters(new ecdomainparameters(curve, g, p.getorder(), biginteger.valueof(p.getcofactor())), random);

                engine.init(param);
                initialised = true;
            }
            else if (params == null && configuration.getecimplicitlyca() != null)
            {
                ecparameterspec p = configuration.getecimplicitlyca();
                this.ecparams = params;

                param = new eckeygenerationparameters(new ecdomainparameters(p.getcurve(), p.getg(), p.getn()), random);

                engine.init(param);
                initialised = true;
            }
            else if (params == null && configuration.getecimplicitlyca() == null)
            {
                throw new invalidalgorithmparameterexception("null parameter passed but no implicitca set");
            }
            else
            {
                throw new invalidalgorithmparameterexception("parameter object not a ecparameterspec");
            }
        }

        public keypair generatekeypair()
        {
            if (!initialised)
            {
                initialize(strength, new securerandom());
            }

            asymmetriccipherkeypair     pair = engine.generatekeypair();
            ecpublickeyparameters       pub = (ecpublickeyparameters)pair.getpublic();
            ecprivatekeyparameters      priv = (ecprivatekeyparameters)pair.getprivate();

            if (ecparams instanceof ecparameterspec)
            {
                ecparameterspec p = (ecparameterspec)ecparams;

                bcecpublickey pubkey = new bcecpublickey(algorithm, pub, p, configuration);
                return new keypair(pubkey,
                                   new bcecprivatekey(algorithm, priv, pubkey, p, configuration));
            }
            else if (ecparams == null)
            {
               return new keypair(new bcecpublickey(algorithm, pub, configuration),
                                   new bcecprivatekey(algorithm, priv, configuration));
            }
            else
            {
                java.security.spec.ecparameterspec p = (java.security.spec.ecparameterspec)ecparams;

                bcecpublickey pubkey = new bcecpublickey(algorithm, pub, p, configuration);
                
                return new keypair(pubkey, new bcecprivatekey(algorithm, priv, pubkey, p, configuration));
            }
        }
    }

    public static class ecdsa
        extends ec
    {
        public ecdsa()
        {
            super("ecdsa", bouncycastleprovider.configuration);
        }
    }

    public static class ecdh
        extends ec
    {
        public ecdh()
        {
            super("ecdh", bouncycastleprovider.configuration);
        }
    }

    public static class ecdhc
        extends ec
    {
        public ecdhc()
        {
            super("ecdhc", bouncycastleprovider.configuration);
        }
    }

    public static class ecmqv
        extends ec
    {
        public ecmqv()
        {
            super("ecmqv", bouncycastleprovider.configuration);
        }
    }
}