package org.ripple.bouncycastle.jce.provider;

import java.security.invalidkeyexception;
import java.security.privatekey;
import java.security.publickey;

import javax.crypto.interfaces.dhprivatekey;
import javax.crypto.interfaces.dhpublickey;

import org.ripple.bouncycastle.crypto.params.asymmetrickeyparameter;
import org.ripple.bouncycastle.crypto.params.dhparameters;
import org.ripple.bouncycastle.crypto.params.dhprivatekeyparameters;
import org.ripple.bouncycastle.crypto.params.dhpublickeyparameters;

/**
 * utility class for converting jce/jca dh objects
 * objects into their org.bouncycastle.crypto counterparts.
 */
public class dhutil
{
    static public asymmetrickeyparameter generatepublickeyparameter(
        publickey    key)
        throws invalidkeyexception
    {
        if (key instanceof dhpublickey)
        {
            dhpublickey    k = (dhpublickey)key;

            return new dhpublickeyparameters(k.gety(),
                new dhparameters(k.getparams().getp(), k.getparams().getg(), null, k.getparams().getl()));
        }

        throw new invalidkeyexception("can't identify dh public key.");
    }

    static public asymmetrickeyparameter generateprivatekeyparameter(
        privatekey    key)
        throws invalidkeyexception
    {
        if (key instanceof dhprivatekey)
        {
            dhprivatekey    k = (dhprivatekey)key;

            return new dhprivatekeyparameters(k.getx(),
                new dhparameters(k.getparams().getp(), k.getparams().getg(), null, k.getparams().getl()));
        }
                        
        throw new invalidkeyexception("can't identify dh private key.");
    }
}
