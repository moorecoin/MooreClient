package org.ripple.bouncycastle.crypto.util;

import java.io.ioexception;

import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.dernull;
import org.ripple.bouncycastle.asn1.pkcs.pkcsobjectidentifiers;
import org.ripple.bouncycastle.asn1.pkcs.privatekeyinfo;
import org.ripple.bouncycastle.asn1.pkcs.rsaprivatekey;
import org.ripple.bouncycastle.asn1.x509.algorithmidentifier;
import org.ripple.bouncycastle.asn1.x509.dsaparameter;
import org.ripple.bouncycastle.asn1.x9.x9objectidentifiers;
import org.ripple.bouncycastle.crypto.params.asymmetrickeyparameter;
import org.ripple.bouncycastle.crypto.params.dsaparameters;
import org.ripple.bouncycastle.crypto.params.dsaprivatekeyparameters;
import org.ripple.bouncycastle.crypto.params.rsakeyparameters;
import org.ripple.bouncycastle.crypto.params.rsaprivatecrtkeyparameters;

/**
 * factory to create asn.1 private key info objects from lightweight private keys.
 */
public class privatekeyinfofactory
{
    /**
     * create a privatekeyinfo representation of a private key.
     *
     * @param privatekey the subjectpublickeyinfo encoding
     * @return the appropriate key parameter
     * @throws java.io.ioexception on an error encoding the key
     */
    public static privatekeyinfo createprivatekeyinfo(asymmetrickeyparameter privatekey) throws ioexception
    {
        if (privatekey instanceof rsakeyparameters)
        {
            rsaprivatecrtkeyparameters priv = (rsaprivatecrtkeyparameters)privatekey;

            return new privatekeyinfo(new algorithmidentifier(pkcsobjectidentifiers.rsaencryption, dernull.instance), new rsaprivatekey(priv.getmodulus(), priv.getpublicexponent(), priv.getexponent(), priv.getp(), priv.getq(), priv.getdp(), priv.getdq(), priv.getqinv()));
        }
        else if (privatekey instanceof dsaprivatekeyparameters)
        {
            dsaprivatekeyparameters priv = (dsaprivatekeyparameters)privatekey;
            dsaparameters params = priv.getparameters();

            return new privatekeyinfo(new algorithmidentifier(x9objectidentifiers.id_dsa, new dsaparameter(params.getp(), params.getq(), params.getg())), new asn1integer(priv.getx()));
        }
        else
        {
            throw new ioexception("key parameters not recognised.");
        }
    }
}
