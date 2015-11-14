package org.ripple.bouncycastle.jcajce.provider.asymmetric.dh;

import java.io.ioexception;
import java.security.invalidkeyexception;
import java.security.key;
import java.security.privatekey;
import java.security.publickey;
import java.security.spec.invalidkeyspecexception;
import java.security.spec.keyspec;

import javax.crypto.interfaces.dhprivatekey;
import javax.crypto.interfaces.dhpublickey;
import javax.crypto.spec.dhprivatekeyspec;
import javax.crypto.spec.dhpublickeyspec;

import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.pkcs.pkcsobjectidentifiers;
import org.ripple.bouncycastle.asn1.pkcs.privatekeyinfo;
import org.ripple.bouncycastle.asn1.x509.subjectpublickeyinfo;
import org.ripple.bouncycastle.asn1.x9.x9objectidentifiers;
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
        if (spec.isassignablefrom(dhprivatekeyspec.class) && key instanceof dhprivatekey)
        {
            dhprivatekey k = (dhprivatekey)key;

            return new dhprivatekeyspec(k.getx(), k.getparams().getp(), k.getparams().getg());
        }
        else if (spec.isassignablefrom(dhpublickeyspec.class) && key instanceof dhpublickey)
        {
            dhpublickey k = (dhpublickey)key;

            return new dhpublickeyspec(k.gety(), k.getparams().getp(), k.getparams().getg());
        }

        return super.enginegetkeyspec(key, spec);
    }

    protected key enginetranslatekey(
        key key)
        throws invalidkeyexception
    {
        if (key instanceof dhpublickey)
        {
            return new bcdhpublickey((dhpublickey)key);
        }
        else if (key instanceof dhprivatekey)
        {
            return new bcdhprivatekey((dhprivatekey)key);
        }

        throw new invalidkeyexception("key type unknown");
    }

    protected privatekey enginegenerateprivate(
        keyspec keyspec)
        throws invalidkeyspecexception
    {
        if (keyspec instanceof dhprivatekeyspec)
        {
            return new bcdhprivatekey((dhprivatekeyspec)keyspec);
        }

        return super.enginegenerateprivate(keyspec);
    }

    protected publickey enginegeneratepublic(
        keyspec keyspec)
        throws invalidkeyspecexception
    {
        if (keyspec instanceof dhpublickeyspec)
        {
            return new bcdhpublickey((dhpublickeyspec)keyspec);
        }

        return super.enginegeneratepublic(keyspec);
    }

    public privatekey generateprivate(privatekeyinfo keyinfo)
        throws ioexception
    {
        asn1objectidentifier algoid = keyinfo.getprivatekeyalgorithm().getalgorithm();

        if (algoid.equals(pkcsobjectidentifiers.dhkeyagreement))
        {
            return new bcdhprivatekey(keyinfo);
        }
        else if (algoid.equals(x9objectidentifiers.dhpublicnumber))
        {
            return new bcdhprivatekey(keyinfo);
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

        if (algoid.equals(pkcsobjectidentifiers.dhkeyagreement))
        {
            return new bcdhpublickey(keyinfo);
        }
        else if (algoid.equals(x9objectidentifiers.dhpublicnumber))
        {
            return new bcdhpublickey(keyinfo);
        }
        else
        {
            throw new ioexception("algorithm identifier " + algoid + " in key not recognised");
        }
    }
}
