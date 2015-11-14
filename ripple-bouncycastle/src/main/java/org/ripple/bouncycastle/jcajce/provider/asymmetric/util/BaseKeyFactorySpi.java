package org.ripple.bouncycastle.jcajce.provider.asymmetric.util;

import java.io.ioexception;
import java.security.key;
import java.security.privatekey;
import java.security.publickey;
import java.security.spec.invalidkeyspecexception;
import java.security.spec.keyspec;
import java.security.spec.pkcs8encodedkeyspec;
import java.security.spec.x509encodedkeyspec;

import org.ripple.bouncycastle.asn1.pkcs.privatekeyinfo;
import org.ripple.bouncycastle.asn1.x509.subjectpublickeyinfo;
import org.ripple.bouncycastle.jcajce.provider.util.asymmetrickeyinfoconverter;

public abstract class basekeyfactoryspi
    extends java.security.keyfactoryspi
    implements asymmetrickeyinfoconverter
{
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
                throw new invalidkeyspecexception("encoded key spec not recognised");
            }
        }
        else
        {
            throw new invalidkeyspecexception("key spec not recognised");
        }
    }

    protected publickey enginegeneratepublic(
        keyspec keyspec)
        throws invalidkeyspecexception
    {
        if (keyspec instanceof x509encodedkeyspec)
        {
            try
            {
                return generatepublic(subjectpublickeyinfo.getinstance(((x509encodedkeyspec)keyspec).getencoded()));
            }
            catch (exception e)
            {
                throw new invalidkeyspecexception("encoded key spec not recognised");
            }
        }
        else
        {
            throw new invalidkeyspecexception("key spec not recognised");
        }
    }

    protected keyspec enginegetkeyspec(
        key key,
        class spec)
        throws invalidkeyspecexception
    {
        if (spec.isassignablefrom(pkcs8encodedkeyspec.class) && key.getformat().equals("pkcs#8"))
        {
            return new pkcs8encodedkeyspec(key.getencoded());
        }
        else if (spec.isassignablefrom(x509encodedkeyspec.class) && key.getformat().equals("x.509"))
        {
            return new x509encodedkeyspec(key.getencoded());
        }

        throw new invalidkeyspecexception("not implemented yet " + key + " " + spec);
    }
}
