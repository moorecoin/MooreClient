package org.ripple.bouncycastle.jcajce.provider.asymmetric.dsa;

import java.io.ioexception;
import java.security.invalidkeyexception;
import java.security.key;
import java.security.privatekey;
import java.security.publickey;
import java.security.interfaces.dsaprivatekey;
import java.security.interfaces.dsapublickey;
import java.security.spec.dsaprivatekeyspec;
import java.security.spec.dsapublickeyspec;
import java.security.spec.invalidkeyspecexception;
import java.security.spec.keyspec;

import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.pkcs.privatekeyinfo;
import org.ripple.bouncycastle.asn1.x509.subjectpublickeyinfo;
import org.ripple.bouncycastle.jcajce.provider.asymmetric.util.basekeyfactoryspi;

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
        if (spec.isassignablefrom(dsapublickeyspec.class) && key instanceof dsapublickey)
        {
            dsapublickey k = (dsapublickey)key;

            return new dsapublickeyspec(k.gety(), k.getparams().getp(), k.getparams().getq(), k.getparams().getg());
        }
        else if (spec.isassignablefrom(dsaprivatekeyspec.class) && key instanceof java.security.interfaces.dsaprivatekey)
        {
            java.security.interfaces.dsaprivatekey k = (java.security.interfaces.dsaprivatekey)key;

            return new dsaprivatekeyspec(k.getx(), k.getparams().getp(), k.getparams().getq(), k.getparams().getg());
        }

        return super.enginegetkeyspec(key, spec);
    }

    protected key enginetranslatekey(
        key key)
        throws invalidkeyexception
    {
        if (key instanceof dsapublickey)
        {
            return new bcdsapublickey((dsapublickey)key);
        }
        else if (key instanceof dsaprivatekey)
        {
            return new bcdsaprivatekey((dsaprivatekey)key);
        }

        throw new invalidkeyexception("key type unknown");
    }

    public privatekey generateprivate(privatekeyinfo keyinfo)
        throws ioexception
    {
        asn1objectidentifier algoid = keyinfo.getprivatekeyalgorithm().getalgorithm();

        if (dsautil.isdsaoid(algoid))
        {
            return new bcdsaprivatekey(keyinfo);
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

        if (dsautil.isdsaoid(algoid))
        {
            return new bcdsapublickey(keyinfo);
        }
        else
        {
            throw new ioexception("algorithm identifier " + algoid + " in key not recognised");
        }
    }

    protected privatekey enginegenerateprivate(
        keyspec keyspec)
        throws invalidkeyspecexception
    {
        if (keyspec instanceof dsaprivatekeyspec)
        {
            return new bcdsaprivatekey((dsaprivatekeyspec)keyspec);
        }

        return super.enginegenerateprivate(keyspec);
    }

    protected publickey enginegeneratepublic(
        keyspec keyspec)
        throws invalidkeyspecexception
    {
        if (keyspec instanceof dsapublickeyspec)
        {
            return new bcdsapublickey((dsapublickeyspec)keyspec);
        }

        return super.enginegeneratepublic(keyspec);
    }
}
