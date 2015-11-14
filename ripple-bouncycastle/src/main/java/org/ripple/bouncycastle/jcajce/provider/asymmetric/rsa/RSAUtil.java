package org.ripple.bouncycastle.jcajce.provider.asymmetric.rsa;

import java.security.interfaces.rsaprivatecrtkey;
import java.security.interfaces.rsaprivatekey;
import java.security.interfaces.rsapublickey;

import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.pkcs.pkcsobjectidentifiers;
import org.ripple.bouncycastle.asn1.x509.x509objectidentifiers;
import org.ripple.bouncycastle.crypto.params.rsakeyparameters;
import org.ripple.bouncycastle.crypto.params.rsaprivatecrtkeyparameters;

/**
 * utility class for converting java.security rsa objects into their
 * org.bouncycastle.crypto counterparts.
 */
public class rsautil
{
    public static final asn1objectidentifier[] rsaoids =
    {
        pkcsobjectidentifiers.rsaencryption,
        x509objectidentifiers.id_ea_rsa,
        pkcsobjectidentifiers.id_rsaes_oaep,
        pkcsobjectidentifiers.id_rsassa_pss
    };

    public static boolean isrsaoid(
        asn1objectidentifier algoid)
    {
        for (int i = 0; i != rsaoids.length; i++)
        {
            if (algoid.equals(rsaoids[i]))
            {
                return true;
            }
        }

        return false;
    }

    static rsakeyparameters generatepublickeyparameter(
        rsapublickey key)
    {
        return new rsakeyparameters(false, key.getmodulus(), key.getpublicexponent());

    }

    static rsakeyparameters generateprivatekeyparameter(
        rsaprivatekey key)
    {
        if (key instanceof rsaprivatecrtkey)
        {
            rsaprivatecrtkey k = (rsaprivatecrtkey)key;

            return new rsaprivatecrtkeyparameters(k.getmodulus(),
                k.getpublicexponent(), k.getprivateexponent(),
                k.getprimep(), k.getprimeq(), k.getprimeexponentp(), k.getprimeexponentq(), k.getcrtcoefficient());
        }
        else
        {
            rsaprivatekey k = key;

            return new rsakeyparameters(true, k.getmodulus(), k.getprivateexponent());
        }
    }
}
