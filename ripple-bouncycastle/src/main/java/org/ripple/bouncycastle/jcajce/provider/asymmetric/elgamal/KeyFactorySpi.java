package org.ripple.bouncycastle.jcajce.provider.asymmetric.elgamal;

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
import org.ripple.bouncycastle.asn1.oiw.oiwobjectidentifiers;
import org.ripple.bouncycastle.asn1.pkcs.pkcsobjectidentifiers;
import org.ripple.bouncycastle.asn1.pkcs.privatekeyinfo;
import org.ripple.bouncycastle.asn1.x509.subjectpublickeyinfo;
import org.ripple.bouncycastle.asn1.x9.x9objectidentifiers;
import org.ripple.bouncycastle.jcajce.provider.asymmetric.util.basekeyfactoryspi;
import org.ripple.bouncycastle.jce.interfaces.elgamalprivatekey;
import org.ripple.bouncycastle.jce.interfaces.elgamalpublickey;
import org.ripple.bouncycastle.jce.spec.elgamalprivatekeyspec;
import org.ripple.bouncycastle.jce.spec.elgamalpublickeyspec;

public class keyfactoryspi
    extends basekeyfactoryspi
{
    public keyfactoryspi()
    {
    }

    protected privatekey enginegenerateprivate(
        keyspec keyspec)
        throws invalidkeyspecexception
    {
        if (keyspec instanceof elgamalprivatekeyspec)
        {
            return new bcelgamalprivatekey((elgamalprivatekeyspec)keyspec);
        }
        else if (keyspec instanceof dhprivatekeyspec)
        {
            return new bcelgamalprivatekey((dhprivatekeyspec)keyspec);
        }

        return super.enginegenerateprivate(keyspec);
    }

    protected publickey enginegeneratepublic(
        keyspec keyspec)
        throws invalidkeyspecexception
    {
        if (keyspec instanceof elgamalpublickeyspec)
        {
            return new bcelgamalpublickey((elgamalpublickeyspec)keyspec);
        }
        else if (keyspec instanceof dhpublickeyspec)
        {
            return new bcelgamalpublickey((dhpublickeyspec)keyspec);
        }
        return super.enginegeneratepublic(keyspec);
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
            return new bcelgamalpublickey((dhpublickey)key);
        }
        else if (key instanceof dhprivatekey)
        {
            return new bcelgamalprivatekey((dhprivatekey)key);
        }
        else if (key instanceof elgamalpublickey)
        {
            return new bcelgamalpublickey((elgamalpublickey)key);
        }
        else if (key instanceof elgamalprivatekey)
        {
            return new bcelgamalprivatekey((elgamalprivatekey)key);
        }

        throw new invalidkeyexception("key type unknown");
    }

    public privatekey generateprivate(privatekeyinfo info)
        throws ioexception
    {
        asn1objectidentifier algoid = info.getprivatekeyalgorithm().getalgorithm();

        if (algoid.equals(pkcsobjectidentifiers.dhkeyagreement))
        {
            return new bcelgamalprivatekey(info);
        }
        else if (algoid.equals(x9objectidentifiers.dhpublicnumber))
        {
            return new bcelgamalprivatekey(info);
        }
        else if (algoid.equals(oiwobjectidentifiers.elgamalalgorithm))
        {
            return new bcelgamalprivatekey(info);
        }
        else
        {
            throw new ioexception("algorithm identifier " + algoid + " in key not recognised");
        }
    }

    public publickey generatepublic(subjectpublickeyinfo info)
        throws ioexception
    {
        asn1objectidentifier algoid = info.getalgorithm().getalgorithm();

        if (algoid.equals(pkcsobjectidentifiers.dhkeyagreement))
        {
            return new bcelgamalpublickey(info);
        }
        else if (algoid.equals(x9objectidentifiers.dhpublicnumber))
        {
            return new bcelgamalpublickey(info);
        }
        else if (algoid.equals(oiwobjectidentifiers.elgamalalgorithm))
        {
            return new bcelgamalpublickey(info);
        }
        else
        {
            throw new ioexception("algorithm identifier " + algoid + " in key not recognised");
        }
    }
}
