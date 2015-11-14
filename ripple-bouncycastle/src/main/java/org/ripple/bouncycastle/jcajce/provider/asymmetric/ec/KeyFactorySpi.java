package org.ripple.bouncycastle.jcajce.provider.asymmetric.ec;

import java.io.ioexception;
import java.security.invalidkeyexception;
import java.security.key;
import java.security.privatekey;
import java.security.publickey;
import java.security.interfaces.ecprivatekey;
import java.security.interfaces.ecpublickey;
import java.security.spec.invalidkeyspecexception;
import java.security.spec.keyspec;

import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.pkcs.privatekeyinfo;
import org.ripple.bouncycastle.asn1.x509.subjectpublickeyinfo;
import org.ripple.bouncycastle.asn1.x9.x9objectidentifiers;
import org.ripple.bouncycastle.jcajce.provider.asymmetric.util.basekeyfactoryspi;
import org.ripple.bouncycastle.jcajce.provider.asymmetric.util.ec5util;
import org.ripple.bouncycastle.jcajce.provider.config.providerconfiguration;
import org.ripple.bouncycastle.jcajce.provider.util.asymmetrickeyinfoconverter;
import org.ripple.bouncycastle.jce.provider.bouncycastleprovider;
import org.ripple.bouncycastle.jce.spec.ecparameterspec;
import org.ripple.bouncycastle.jce.spec.ecprivatekeyspec;
import org.ripple.bouncycastle.jce.spec.ecpublickeyspec;

public class keyfactoryspi
    extends basekeyfactoryspi
    implements asymmetrickeyinfoconverter
{
    string algorithm;
    providerconfiguration configuration;

    keyfactoryspi(
        string algorithm,
        providerconfiguration configuration)
    {
        this.algorithm = algorithm;
        this.configuration = configuration;
    }

    protected key enginetranslatekey(
        key    key)
        throws invalidkeyexception
    {
        if (key instanceof ecpublickey)
        {
            return new bcecpublickey((ecpublickey)key, configuration);
        }
        else if (key instanceof ecprivatekey)
        {
            return new bcecprivatekey((ecprivatekey)key, configuration);
        }

        throw new invalidkeyexception("key type unknown");
    }

    protected keyspec enginegetkeyspec(
        key    key,
        class    spec)
    throws invalidkeyspecexception
    {
       if (spec.isassignablefrom(java.security.spec.ecpublickeyspec.class) && key instanceof ecpublickey)
       {
           ecpublickey k = (ecpublickey)key;
           if (k.getparams() != null)
           {
               return new java.security.spec.ecpublickeyspec(k.getw(), k.getparams());
           }
           else
           {
               ecparameterspec implicitspec = bouncycastleprovider.configuration.getecimplicitlyca();

               return new java.security.spec.ecpublickeyspec(k.getw(), ec5util.convertspec(ec5util.convertcurve(implicitspec.getcurve(), implicitspec.getseed()), implicitspec));
           }
       }
       else if (spec.isassignablefrom(java.security.spec.ecprivatekeyspec.class) && key instanceof ecprivatekey)
       {
           ecprivatekey k = (ecprivatekey)key;

           if (k.getparams() != null)
           {
               return new java.security.spec.ecprivatekeyspec(k.gets(), k.getparams());
           }
           else
           {
               ecparameterspec implicitspec = bouncycastleprovider.configuration.getecimplicitlyca();

               return new java.security.spec.ecprivatekeyspec(k.gets(), ec5util.convertspec(ec5util.convertcurve(implicitspec.getcurve(), implicitspec.getseed()), implicitspec)); 
           }
       }
       else if (spec.isassignablefrom(org.ripple.bouncycastle.jce.spec.ecpublickeyspec.class) && key instanceof ecpublickey)
       {
           ecpublickey k = (ecpublickey)key;
           if (k.getparams() != null)
           {
               return new org.ripple.bouncycastle.jce.spec.ecpublickeyspec(ec5util.convertpoint(k.getparams(), k.getw(), false), ec5util.convertspec(k.getparams(), false));
           }
           else
           {
               ecparameterspec implicitspec = bouncycastleprovider.configuration.getecimplicitlyca();

               return new org.ripple.bouncycastle.jce.spec.ecpublickeyspec(ec5util.convertpoint(k.getparams(), k.getw(), false), implicitspec);
           }
       }
       else if (spec.isassignablefrom(org.ripple.bouncycastle.jce.spec.ecprivatekeyspec.class) && key instanceof ecprivatekey)
       {
           ecprivatekey k = (ecprivatekey)key;

           if (k.getparams() != null)
           {
               return new org.ripple.bouncycastle.jce.spec.ecprivatekeyspec(k.gets(), ec5util.convertspec(k.getparams(), false));
           }
           else
           {
               ecparameterspec implicitspec = bouncycastleprovider.configuration.getecimplicitlyca();

               return new org.ripple.bouncycastle.jce.spec.ecprivatekeyspec(k.gets(), implicitspec);
           }
       }

       return super.enginegetkeyspec(key, spec);
    }

    protected privatekey enginegenerateprivate(
        keyspec keyspec)
        throws invalidkeyspecexception
    {
        if (keyspec instanceof ecprivatekeyspec)
        {
            return new bcecprivatekey(algorithm, (ecprivatekeyspec)keyspec, configuration);
        }
        else if (keyspec instanceof java.security.spec.ecprivatekeyspec)
        {
            return new bcecprivatekey(algorithm, (java.security.spec.ecprivatekeyspec)keyspec, configuration);
        }

        return super.enginegenerateprivate(keyspec);
    }

    protected publickey enginegeneratepublic(
        keyspec keyspec)
        throws invalidkeyspecexception
    {
        if (keyspec instanceof ecpublickeyspec)
        {
            return new bcecpublickey(algorithm, (ecpublickeyspec)keyspec, configuration);
        }
        else if (keyspec instanceof java.security.spec.ecpublickeyspec)
        {
            return new bcecpublickey(algorithm, (java.security.spec.ecpublickeyspec)keyspec, configuration);
        }

        return super.enginegeneratepublic(keyspec);
    }

    public privatekey generateprivate(privatekeyinfo keyinfo)
        throws ioexception
    {
        asn1objectidentifier algoid = keyinfo.getprivatekeyalgorithm().getalgorithm();

        if (algoid.equals(x9objectidentifiers.id_ecpublickey))
        {
            return new bcecprivatekey(algorithm, keyinfo, configuration);
        }
        else
        {
            throw new ioexception("algorithm identifier " + algoid + " in key not recognised");
        }
    }

    public publickey generatepublic(subjectpublickeyinfo keyinfo)
        throws ioexception
    {
        asn1objectidentifier algoid = keyinfo.getalgorithm().getalgorithm();

        if (algoid.equals(x9objectidentifiers.id_ecpublickey))
        {
            return new bcecpublickey(algorithm, keyinfo, configuration);
        }
        else
        {
            throw new ioexception("algorithm identifier " + algoid + " in key not recognised");
        }
    }

    public static class ec
        extends keyfactoryspi
    {
        public ec()
        {
            super("ec", bouncycastleprovider.configuration);
        }
    }

    public static class ecdsa
        extends keyfactoryspi
    {
        public ecdsa()
        {
            super("ecdsa", bouncycastleprovider.configuration);
        }
    }

    public static class ecgost3410
        extends keyfactoryspi
    {
        public ecgost3410()
        {
            super("ecgost3410", bouncycastleprovider.configuration);
        }
    }

    public static class ecdh
        extends keyfactoryspi
    {
        public ecdh()
        {
            super("ecdh", bouncycastleprovider.configuration);
        }
    }

    public static class ecdhc
        extends keyfactoryspi
    {
        public ecdhc()
        {
            super("ecdhc", bouncycastleprovider.configuration);
        }
    }

    public static class ecmqv
        extends keyfactoryspi
    {
        public ecmqv()
        {
            super("ecmqv", bouncycastleprovider.configuration);
        }
    }
}