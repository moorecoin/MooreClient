package org.ripple.bouncycastle.pqc.jcajce.provider.mceliece;

import java.security.invalidkeyexception;
import java.security.privatekey;
import java.security.publickey;

import org.ripple.bouncycastle.crypto.params.asymmetrickeyparameter;
import org.ripple.bouncycastle.pqc.crypto.mceliece.mceliececca2privatekeyparameters;
import org.ripple.bouncycastle.pqc.crypto.mceliece.mceliececca2publickeyparameters;

/**
 * utility class for converting jce/jca mceliececca2 objects
 * objects into their org.bouncycastle.crypto counterparts.
 */
public class mceliececca2keystoparams
{


    static public asymmetrickeyparameter generatepublickeyparameter(
        publickey key)
        throws invalidkeyexception
    {
        if (key instanceof bcmceliececca2publickey)
        {
            bcmceliececca2publickey k = (bcmceliececca2publickey)key;

            return new mceliececca2publickeyparameters(k.getoidstring(), k.getn(), k.gett(), k.getg(), k.getmceliececca2parameters());
        }

        throw new invalidkeyexception("can't identify mceliececca2 public key: " + key.getclass().getname());
    }


    static public asymmetrickeyparameter generateprivatekeyparameter(
        privatekey key)
        throws invalidkeyexception
    {
        if (key instanceof bcmceliececca2privatekey)
        {
            bcmceliececca2privatekey k = (bcmceliececca2privatekey)key;
            return new mceliececca2privatekeyparameters(k.getoidstring(), k.getn(), k.getk(), k.getfield(), k.getgoppapoly(),
                k.getp(), k.geth(), k.getqinv(), k.getmceliececca2parameters());
        }

        throw new invalidkeyexception("can't identify mceliececca2 private key.");
    }
}
