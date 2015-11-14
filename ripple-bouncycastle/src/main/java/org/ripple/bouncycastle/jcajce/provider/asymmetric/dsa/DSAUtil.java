package org.ripple.bouncycastle.jcajce.provider.asymmetric.dsa;

import java.security.invalidkeyexception;
import java.security.privatekey;
import java.security.publickey;
import java.security.interfaces.dsaprivatekey;
import java.security.interfaces.dsapublickey;

import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.oiw.oiwobjectidentifiers;
import org.ripple.bouncycastle.asn1.x9.x9objectidentifiers;
import org.ripple.bouncycastle.crypto.params.asymmetrickeyparameter;
import org.ripple.bouncycastle.crypto.params.dsaparameters;
import org.ripple.bouncycastle.crypto.params.dsaprivatekeyparameters;
import org.ripple.bouncycastle.crypto.params.dsapublickeyparameters;

/**
 * utility class for converting jce/jca dsa objects
 * objects into their org.bouncycastle.crypto counterparts.
 */
public class dsautil
{
    public static final asn1objectidentifier[] dsaoids =
    {
        x9objectidentifiers.id_dsa,
        oiwobjectidentifiers.dsawithsha1
    };

    public static boolean isdsaoid(
        asn1objectidentifier algoid)
    {
        for (int i = 0; i != dsaoids.length; i++)
        {
            if (algoid.equals(dsaoids[i]))
            {
                return true;
            }
        }

        return false;
    }

    static public asymmetrickeyparameter generatepublickeyparameter(
        publickey    key)
        throws invalidkeyexception
    {
        if (key instanceof dsapublickey)
        {
            dsapublickey    k = (dsapublickey)key;

            return new dsapublickeyparameters(k.gety(),
                new dsaparameters(k.getparams().getp(), k.getparams().getq(), k.getparams().getg()));
        }

        throw new invalidkeyexception("can't identify dsa public key: " + key.getclass().getname());
    }

    static public asymmetrickeyparameter generateprivatekeyparameter(
        privatekey    key)
        throws invalidkeyexception
    {
        if (key instanceof dsaprivatekey)
        {
            dsaprivatekey    k = (dsaprivatekey)key;

            return new dsaprivatekeyparameters(k.getx(),
                new dsaparameters(k.getparams().getp(), k.getparams().getq(), k.getparams().getg()));
        }
                        
        throw new invalidkeyexception("can't identify dsa private key.");
    }
}
