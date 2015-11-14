package org.ripple.bouncycastle.jcajce.provider.asymmetric.rsa;

import java.io.ioexception;
import java.security.invalidkeyexception;
import java.security.key;
import java.security.privatekey;
import java.security.publickey;
import java.security.interfaces.rsaprivatecrtkey;
import java.security.interfaces.rsapublickey;
import java.security.spec.invalidkeyspecexception;
import java.security.spec.keyspec;
import java.security.spec.pkcs8encodedkeyspec;
import java.security.spec.rsaprivatecrtkeyspec;
import java.security.spec.rsaprivatekeyspec;
import java.security.spec.rsapublickeyspec;

import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.pkcs.privatekeyinfo;
import org.ripple.bouncycastle.asn1.pkcs.rsaprivatekey;
import org.ripple.bouncycastle.asn1.x509.subjectpublickeyinfo;
import org.ripple.bouncycastle.jcajce.provider.asymmetric.util.basekeyfactoryspi;
import org.ripple.bouncycastle.jcajce.provider.asymmetric.util.extendedinvalidkeyspecexception;

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
        if (spec.isassignablefrom(rsapublickeyspec.class) && key instanceof rsapublickey)
        {
            rsapublickey k = (rsapublickey)key;

            return new rsapublickeyspec(k.getmodulus(), k.getpublicexponent());
        }
        else if (spec.isassignablefrom(rsaprivatekeyspec.class) && key instanceof java.security.interfaces.rsaprivatekey)
        {
            java.security.interfaces.rsaprivatekey k = (java.security.interfaces.rsaprivatekey)key;

            return new rsaprivatekeyspec(k.getmodulus(), k.getprivateexponent());
        }
        else if (spec.isassignablefrom(rsaprivatecrtkeyspec.class) && key instanceof rsaprivatecrtkey)
        {
            rsaprivatecrtkey k = (rsaprivatecrtkey)key;

            return new rsaprivatecrtkeyspec(
                k.getmodulus(), k.getpublicexponent(),
                k.getprivateexponent(),
                k.getprimep(), k.getprimeq(),
                k.getprimeexponentp(), k.getprimeexponentq(),
                k.getcrtcoefficient());
        }

        return super.enginegetkeyspec(key, spec);
    }

    protected key enginetranslatekey(
        key key)
        throws invalidkeyexception
    {
        if (key instanceof rsapublickey)
        {
            return new bcrsapublickey((rsapublickey)key);
        }
        else if (key instanceof rsaprivatecrtkey)
        {
            return new bcrsaprivatecrtkey((rsaprivatecrtkey)key);
        }
        else if (key instanceof java.security.interfaces.rsaprivatekey)
        {
            return new bcrsaprivatekey((java.security.interfaces.rsaprivatekey)key);
        }

        throw new invalidkeyexception("key type unknown");
    }

    protected privatekey enginegenerateprivate(
        keyspec keyspec)
        throws invalidkeyspecexception
    {
        if (keyspec instanceof pkcs8encodedkeyspec)
        {
            try
            {
                return generateprivate(privatekeyinfo.getinstance(((pkcs8encodedkeyspec)keyspec).getencoded()));
            }
            catch (exception e)
            {
                //
                // in case it's just a rsaprivatekey object... -- openssl produces these
                //
                try
                {
                    return new bcrsaprivatecrtkey(
                        rsaprivatekey.getinstance(((pkcs8encodedkeyspec)keyspec).getencoded()));
                }
                catch (exception ex)
                {
                    throw new extendedinvalidkeyspecexception("unable to process key spec: " + e.tostring(), e);
                }
            }
        }
        else if (keyspec instanceof rsaprivatecrtkeyspec)
        {
            return new bcrsaprivatecrtkey((rsaprivatecrtkeyspec)keyspec);
        }
        else if (keyspec instanceof rsaprivatekeyspec)
        {
            return new bcrsaprivatekey((rsaprivatekeyspec)keyspec);
        }

        throw new invalidkeyspecexception("unknown keyspec type: " + keyspec.getclass().getname());
    }

    protected publickey enginegeneratepublic(
        keyspec keyspec)
        throws invalidkeyspecexception
    {
        if (keyspec instanceof rsapublickeyspec)
        {
            return new bcrsapublickey((rsapublickeyspec)keyspec);
        }

        return super.enginegeneratepublic(keyspec);
    }

    public privatekey generateprivate(privatekeyinfo keyinfo)
        throws ioexception
    {
        asn1objectidentifier algoid = keyinfo.getprivatekeyalgorithm().getalgorithm();

        if (rsautil.isrsaoid(algoid))
        {
            return new bcrsaprivatecrtkey(keyinfo);
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

        if (rsautil.isrsaoid(algoid))
        {
            return new bcrsapublickey(keyinfo);
        }
        else
        {
            throw new ioexception("algorithm identifier " + algoid + " in key not recognised");
        }
    }
}
