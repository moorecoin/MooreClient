package org.ripple.bouncycastle.jcajce.provider.asymmetric.gost;

import java.io.ioexception;
import java.security.invalidkeyexception;
import java.security.key;
import java.security.privatekey;
import java.security.publickey;
import java.security.spec.invalidkeyspecexception;
import java.security.spec.keyspec;

import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.cryptopro.cryptoproobjectidentifiers;
import org.ripple.bouncycastle.asn1.pkcs.privatekeyinfo;
import org.ripple.bouncycastle.asn1.x509.subjectpublickeyinfo;
import org.ripple.bouncycastle.jcajce.provider.asymmetric.util.basekeyfactoryspi;
import org.ripple.bouncycastle.jce.interfaces.gost3410privatekey;
import org.ripple.bouncycastle.jce.interfaces.gost3410publickey;
import org.ripple.bouncycastle.jce.spec.gost3410privatekeyspec;
import org.ripple.bouncycastle.jce.spec.gost3410publickeyparametersetspec;
import org.ripple.bouncycastle.jce.spec.gost3410publickeyspec;

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
        if (spec.isassignablefrom(gost3410publickeyspec.class) && key instanceof gost3410publickey)
        {
            gost3410publickey k = (gost3410publickey)key;
            gost3410publickeyparametersetspec parameters = k.getparameters().getpublickeyparameters();

            return new gost3410publickeyspec(k.gety(), parameters.getp(), parameters.getq(), parameters.geta());
        }
        else if (spec.isassignablefrom(gost3410privatekeyspec.class) && key instanceof gost3410privatekey)
        {
            gost3410privatekey k = (gost3410privatekey)key;
            gost3410publickeyparametersetspec parameters = k.getparameters().getpublickeyparameters();

            return new gost3410privatekeyspec(k.getx(), parameters.getp(), parameters.getq(), parameters.geta());
        }

        return super.enginegetkeyspec(key, spec);
    }

    protected key enginetranslatekey(
        key key)
        throws invalidkeyexception
    {
        if (key instanceof gost3410publickey)
        {
            return new bcgost3410publickey((gost3410publickey)key);
        }
        else if (key instanceof gost3410privatekey)
        {
            return new bcgost3410privatekey((gost3410privatekey)key);
        }

        throw new invalidkeyexception("key type unknown");
    }

    protected privatekey enginegenerateprivate(
            keyspec    keyspec)
    throws invalidkeyspecexception
    {
        if (keyspec instanceof gost3410privatekeyspec)
        {
            return new bcgost3410privatekey((gost3410privatekeyspec)keyspec);
        }

        return super.enginegenerateprivate(keyspec);
    }

    protected publickey enginegeneratepublic(
            keyspec    keyspec)
    throws invalidkeyspecexception
    {
        if (keyspec instanceof gost3410publickeyspec)
        {
            return new bcgost3410publickey((gost3410publickeyspec)keyspec);
        }

        return super.enginegeneratepublic(keyspec);
    }

    public privatekey generateprivate(privatekeyinfo keyinfo)
        throws ioexception
    {
        asn1objectidentifier algoid = keyinfo.getprivatekeyalgorithm().getalgorithm();

        if (algoid.equals(cryptoproobjectidentifiers.gostr3410_94))
        {
            return new bcgost3410privatekey(keyinfo);
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

        if (algoid.equals(cryptoproobjectidentifiers.gostr3410_94))
        {
            return new bcgost3410publickey(keyinfo);
        }
        else
        {
            throw new ioexception("algorithm identifier " + algoid + " in key not recognised");
        }
    }
}
