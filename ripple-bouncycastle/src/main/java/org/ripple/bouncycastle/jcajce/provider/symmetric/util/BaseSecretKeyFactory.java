package org.ripple.bouncycastle.jcajce.provider.symmetric.util;

import java.lang.reflect.constructor;
import java.security.invalidkeyexception;
import java.security.spec.invalidkeyspecexception;
import java.security.spec.keyspec;

import javax.crypto.secretkey;
import javax.crypto.secretkeyfactoryspi;
import javax.crypto.spec.secretkeyspec;

import org.ripple.bouncycastle.asn1.asn1objectidentifier;

public class basesecretkeyfactory
    extends secretkeyfactoryspi
    implements pbe
{
    protected string                algname;
    protected asn1objectidentifier   algoid;

    protected basesecretkeyfactory(
        string algname,
        asn1objectidentifier algoid)
    {
        this.algname = algname;
        this.algoid = algoid;
    }

    protected secretkey enginegeneratesecret(
        keyspec keyspec)
    throws invalidkeyspecexception
    {
        if (keyspec instanceof secretkeyspec)
        {
            return (secretkey)keyspec;
        }

        throw new invalidkeyspecexception("invalid keyspec");
    }

    protected keyspec enginegetkeyspec(
        secretkey key,
        class keyspec)
    throws invalidkeyspecexception
    {
        if (keyspec == null)
        {
            throw new invalidkeyspecexception("keyspec parameter is null");
        }
        if (key == null)
        {
            throw new invalidkeyspecexception("key parameter is null");
        }
        
        if (secretkeyspec.class.isassignablefrom(keyspec))
        {
            return new secretkeyspec(key.getencoded(), algname);
        }

        try
        {
            class[] parameters = { byte[].class };

            constructor c = keyspec.getconstructor(parameters);
            object[]    p = new object[1];

            p[0] = key.getencoded();

            return (keyspec)c.newinstance(p);
        }
        catch (exception e)
        {
            throw new invalidkeyspecexception(e.tostring());
        }
    }

    protected secretkey enginetranslatekey(
        secretkey key)
    throws invalidkeyexception
    {
        if (key == null)
        {
            throw new invalidkeyexception("key parameter is null");
        }
        
        if (!key.getalgorithm().equalsignorecase(algname))
        {
            throw new invalidkeyexception("key not of type " + algname + ".");
        }

        return new secretkeyspec(key.getencoded(), algname);
    }
}
