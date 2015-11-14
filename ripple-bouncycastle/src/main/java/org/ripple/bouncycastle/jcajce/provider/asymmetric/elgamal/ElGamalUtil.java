package org.ripple.bouncycastle.jcajce.provider.asymmetric.elgamal;

import java.security.invalidkeyexception;
import java.security.privatekey;
import java.security.publickey;

import javax.crypto.interfaces.dhprivatekey;
import javax.crypto.interfaces.dhpublickey;

import org.ripple.bouncycastle.crypto.params.asymmetrickeyparameter;
import org.ripple.bouncycastle.crypto.params.elgamalparameters;
import org.ripple.bouncycastle.crypto.params.elgamalprivatekeyparameters;
import org.ripple.bouncycastle.crypto.params.elgamalpublickeyparameters;
import org.ripple.bouncycastle.jce.interfaces.elgamalprivatekey;
import org.ripple.bouncycastle.jce.interfaces.elgamalpublickey;

/**
 * utility class for converting jce/jca elgamal objects
 * objects into their org.bouncycastle.crypto counterparts.
 */
public class elgamalutil
{
    static public asymmetrickeyparameter generatepublickeyparameter(
        publickey    key)
        throws invalidkeyexception
    {
        if (key instanceof elgamalpublickey)
        {
            elgamalpublickey    k = (elgamalpublickey)key;

            return new elgamalpublickeyparameters(k.gety(),
                new elgamalparameters(k.getparameters().getp(), k.getparameters().getg()));
        }
        else if (key instanceof dhpublickey)
        {
            dhpublickey    k = (dhpublickey)key;

            return new elgamalpublickeyparameters(k.gety(),
                new elgamalparameters(k.getparams().getp(), k.getparams().getg()));
        }

        throw new invalidkeyexception("can't identify public key for el gamal.");
    }

    static public asymmetrickeyparameter generateprivatekeyparameter(
        privatekey    key)
        throws invalidkeyexception
    {
        if (key instanceof elgamalprivatekey)
        {
            elgamalprivatekey    k = (elgamalprivatekey)key;

            return new elgamalprivatekeyparameters(k.getx(),
                new elgamalparameters(k.getparameters().getp(), k.getparameters().getg()));
        }
        else if (key instanceof dhprivatekey)
        {
            dhprivatekey    k = (dhprivatekey)key;

            return new elgamalprivatekeyparameters(k.getx(),
                new elgamalparameters(k.getparams().getp(), k.getparams().getg()));
        }
                        
        throw new invalidkeyexception("can't identify private key for el gamal.");
    }
}
