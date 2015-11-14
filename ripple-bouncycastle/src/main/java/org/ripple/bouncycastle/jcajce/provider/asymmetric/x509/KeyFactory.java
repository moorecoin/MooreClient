package org.ripple.bouncycastle.jcajce.provider.asymmetric.x509;

import java.security.invalidkeyexception;
import java.security.key;
import java.security.keyfactoryspi;
import java.security.privatekey;
import java.security.publickey;
import java.security.spec.invalidkeyspecexception;
import java.security.spec.keyspec;
import java.security.spec.pkcs8encodedkeyspec;
import java.security.spec.x509encodedkeyspec;

import org.ripple.bouncycastle.asn1.pkcs.privatekeyinfo;
import org.ripple.bouncycastle.asn1.x509.subjectpublickeyinfo;
import org.ripple.bouncycastle.jce.provider.bouncycastleprovider;

public class keyfactory
    extends keyfactoryspi
{

    protected privatekey enginegenerateprivate(
        keyspec keyspec)
        throws invalidkeyspecexception
    {
        if (keyspec instanceof pkcs8encodedkeyspec)
        {
            try
            {
                privatekeyinfo info = privatekeyinfo.getinstance(((pkcs8encodedkeyspec)keyspec).getencoded());
                privatekey     key = bouncycastleprovider.getprivatekey(info);

                if (key != null)
                {
                    return key;
                }

                throw new invalidkeyspecexception("no factory found for oid: " + info.getprivatekeyalgorithm().getalgorithm());
            }
            catch (exception e)
            {
                throw new invalidkeyspecexception(e.tostring());
            }
        }

        throw new invalidkeyspecexception("unknown keyspec type: " + keyspec.getclass().getname());
    }

    protected publickey enginegeneratepublic(
        keyspec keyspec)
        throws invalidkeyspecexception
    {
        if (keyspec instanceof x509encodedkeyspec)
        {
            try
            {
                subjectpublickeyinfo info = subjectpublickeyinfo.getinstance(((x509encodedkeyspec)keyspec).getencoded());
                publickey            key = bouncycastleprovider.getpublickey(info);

                if (key != null)
                {
                    return key;
                }

                throw new invalidkeyspecexception("no factory found for oid: " + info.getalgorithm().getalgorithm());
            }
            catch (exception e)
            {
                throw new invalidkeyspecexception(e.tostring());
            }
        }

        throw new invalidkeyspecexception("unknown keyspec type: " + keyspec.getclass().getname());
    }

    protected keyspec enginegetkeyspec(key key, class keyspec)
        throws invalidkeyspecexception
    {
        if (keyspec.isassignablefrom(pkcs8encodedkeyspec.class) && key.getformat().equals("pkcs#8"))
        {
            return new pkcs8encodedkeyspec(key.getencoded());
        }
        else if (keyspec.isassignablefrom(x509encodedkeyspec.class) && key.getformat().equals("x.509"))
        {
            return new x509encodedkeyspec(key.getencoded());
        }

        throw new invalidkeyspecexception("not implemented yet " + key + " " + keyspec);
    }

    protected key enginetranslatekey(key key)
        throws invalidkeyexception
    {
        throw new invalidkeyexception("not implemented yet " + key);
    }
}