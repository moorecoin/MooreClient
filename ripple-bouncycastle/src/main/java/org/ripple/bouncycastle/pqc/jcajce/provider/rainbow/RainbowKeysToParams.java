package org.ripple.bouncycastle.pqc.jcajce.provider.rainbow;

import java.security.invalidkeyexception;
import java.security.privatekey;
import java.security.publickey;

import org.ripple.bouncycastle.crypto.params.asymmetrickeyparameter;
import org.ripple.bouncycastle.pqc.crypto.rainbow.rainbowprivatekeyparameters;
import org.ripple.bouncycastle.pqc.crypto.rainbow.rainbowpublickeyparameters;


/**
 * utility class for converting jce/jca rainbow objects
 * objects into their org.bouncycastle.crypto counterparts.
 */

public class rainbowkeystoparams
{
    static public asymmetrickeyparameter generatepublickeyparameter(
        publickey key)
        throws invalidkeyexception
    {
        if (key instanceof bcrainbowpublickey)
        {
            bcrainbowpublickey k = (bcrainbowpublickey)key;

            return new rainbowpublickeyparameters(k.getdoclength(), k.getcoeffquadratic(),
                k.getcoeffsingular(), k.getcoeffscalar());
        }

        throw new invalidkeyexception("can't identify rainbow public key: " + key.getclass().getname());
    }

    static public asymmetrickeyparameter generateprivatekeyparameter(
        privatekey key)
        throws invalidkeyexception
    {
        if (key instanceof bcrainbowprivatekey)
        {
            bcrainbowprivatekey k = (bcrainbowprivatekey)key;
            return new rainbowprivatekeyparameters(k.getinva1(), k.getb1(),
                k.getinva2(), k.getb2(), k.getvi(), k.getlayers());
        }

        throw new invalidkeyexception("can't identify rainbow private key.");
    }
}


