package org.ripple.bouncycastle.jcajce.provider.asymmetric.util;

import java.security.invalidkeyexception;
import java.security.privatekey;
import java.security.publickey;

import org.ripple.bouncycastle.crypto.params.asymmetrickeyparameter;
import org.ripple.bouncycastle.crypto.params.gost3410parameters;
import org.ripple.bouncycastle.crypto.params.gost3410privatekeyparameters;
import org.ripple.bouncycastle.crypto.params.gost3410publickeyparameters;
import org.ripple.bouncycastle.jce.interfaces.gost3410privatekey;
import org.ripple.bouncycastle.jce.interfaces.gost3410publickey;
import org.ripple.bouncycastle.jce.spec.gost3410publickeyparametersetspec;

/**
 * utility class for converting jce/jca gost3410-94 objects
 * objects into their org.bouncycastle.crypto counterparts.
 */
public class gost3410util
{
    static public asymmetrickeyparameter generatepublickeyparameter(
        publickey    key)
        throws invalidkeyexception
    {
        if (key instanceof gost3410publickey)
        {
            gost3410publickey          k = (gost3410publickey)key;
            gost3410publickeyparametersetspec p = k.getparameters().getpublickeyparameters();
            
            return new gost3410publickeyparameters(k.gety(),
                new gost3410parameters(p.getp(), p.getq(), p.geta()));
        }

        throw new invalidkeyexception("can't identify gost3410 public key: " + key.getclass().getname());
    }

    static public asymmetrickeyparameter generateprivatekeyparameter(
        privatekey    key)
        throws invalidkeyexception
    {
        if (key instanceof gost3410privatekey)
        {
            gost3410privatekey         k = (gost3410privatekey)key;
            gost3410publickeyparametersetspec p = k.getparameters().getpublickeyparameters();
            
            return new gost3410privatekeyparameters(k.getx(),
                new gost3410parameters(p.getp(), p.getq(), p.geta()));
        }

        throw new invalidkeyexception("can't identify gost3410 private key.");
    }
}
