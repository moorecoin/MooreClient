package org.ripple.bouncycastle.pqc.jcajce.provider.mceliece;

import java.security.invalidkeyexception;
import java.security.privatekey;
import java.security.publickey;

import org.ripple.bouncycastle.crypto.params.asymmetrickeyparameter;
import org.ripple.bouncycastle.pqc.crypto.mceliece.mcelieceprivatekeyparameters;
import org.ripple.bouncycastle.pqc.crypto.mceliece.mceliecepublickeyparameters;

/**
 * utility class for converting jce/jca mceliece objects
 * objects into their org.bouncycastle.crypto counterparts.
 */
public class mceliecekeystoparams
{


    static public asymmetrickeyparameter generatepublickeyparameter(
        publickey key)
        throws invalidkeyexception
    {
        if (key instanceof bcmceliecepublickey)
        {
            bcmceliecepublickey k = (bcmceliecepublickey)key;

            return new mceliecepublickeyparameters(k.getoidstring(), k.getn(), k.gett(), k.getg(), k.getmcelieceparameters());
        }

        throw new invalidkeyexception("can't identify mceliece public key: " + key.getclass().getname());
    }


    static public asymmetrickeyparameter generateprivatekeyparameter(
        privatekey key)
        throws invalidkeyexception
    {
        if (key instanceof bcmcelieceprivatekey)
        {
            bcmcelieceprivatekey k = (bcmcelieceprivatekey)key;
            return new mcelieceprivatekeyparameters(k.getoidstring(), k.getn(), k.getk(), k.getfield(), k.getgoppapoly(),
                k.getsinv(), k.getp1(), k.getp2(), k.geth(), k.getqinv(), k.getmcelieceparameters());
        }

        throw new invalidkeyexception("can't identify mceliece private key.");
    }
}
