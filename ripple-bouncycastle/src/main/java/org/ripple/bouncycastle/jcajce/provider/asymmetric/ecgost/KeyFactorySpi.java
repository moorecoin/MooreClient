package org.ripple.bouncycastle.jcajce.provider.asymmetric.ecgost;

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
import org.ripple.bouncycastle.asn1.cryptopro.cryptoproobjectidentifiers;
import org.ripple.bouncycastle.asn1.pkcs.privatekeyinfo;
import org.ripple.bouncycastle.asn1.x509.subjectpublickeyinfo;
import org.ripple.bouncycastle.jcajce.provider.asymmetric.util.basekeyfactoryspi;
import org.ripple.bouncycastle.jcajce.provider.asymmetric.util.ec5util;
import org.ripple.bouncycastle.jce.provider.bouncycastleprovider;
import org.ripple.bouncycastle.jce.spec.ecparameterspec;
import org.ripple.bouncycastle.jce.spec.ecprivatekeyspec;
import org.ripple.bouncycastle.jce.spec.ecpublickeyspec;

public class keyfactoryspi
    extends basekeyfactoryspi
{
    public keyfactoryspi()
    {
    }

    protected keyspec enginegetkeyspec(
        key key,
        class spec)
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

    protected key enginetranslatekey(
        key key)
        throws invalidkeyexception
    {
        throw new invalidkeyexception("key type unknown");
    }

    protected privatekey enginegenerateprivate(
        keyspec keyspec)
        throws invalidkeyspecexception
    {
        if (keyspec instanceof ecprivatekeyspec)
        {
            return new bcecgost3410privatekey((ecprivatekeyspec)keyspec);
        }
        else if (keyspec instanceof java.security.spec.ecprivatekeyspec)
        {
            return new bcecgost3410privatekey((java.security.spec.ecprivatekeyspec)keyspec);
        }

        return super.enginegenerateprivate(keyspec);
    }

    protected publickey enginegeneratepublic(
        keyspec keyspec)
        throws invalidkeyspecexception
    {
        if (keyspec instanceof ecpublickeyspec)
        {
            return new bcecgost3410publickey((ecpublickeyspec)keyspec);
        }
        else if (keyspec instanceof java.security.spec.ecpublickeyspec)
        {
            return new bcecgost3410publickey((java.security.spec.ecpublickeyspec)keyspec);
        }

        return super.enginegeneratepublic(keyspec);
    }

    public privatekey generateprivate(privatekeyinfo keyinfo)
        throws ioexception
    {
        asn1objectidentifier algoid = keyinfo.getprivatekeyalgorithm().getalgorithm();

        if (algoid.equals(cryptoproobjectidentifiers.gostr3410_2001))
        {
            return new bcecgost3410privatekey(keyinfo);
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

        if (algoid.equals(cryptoproobjectidentifiers.gostr3410_2001))
        {
            return new bcecgost3410publickey(keyinfo);
        }
        else
        {
            throw new ioexception("algorithm identifier " + algoid + " in key not recognised");
        }
    }
}
