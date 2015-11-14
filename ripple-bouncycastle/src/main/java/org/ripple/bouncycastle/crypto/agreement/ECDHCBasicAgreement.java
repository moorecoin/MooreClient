package org.ripple.bouncycastle.crypto.agreement;

import java.math.biginteger;

import org.ripple.bouncycastle.crypto.basicagreement;
import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.params.ecdomainparameters;
import org.ripple.bouncycastle.crypto.params.ecprivatekeyparameters;
import org.ripple.bouncycastle.crypto.params.ecpublickeyparameters;
import org.ripple.bouncycastle.math.ec.ecpoint;

/**
 * p1363 7.2.2 ecsvdp-dhc
 *
 * ecsvdp-dhc is elliptic curve secret value derivation primitive,
 * diffie-hellman version with cofactor multiplication. it is based on
 * the work of [dh76], [mil86], [kob87], [lmq98] and [kal98a]. this
 * primitive derives a shared secret value from one party's private key
 * and another party's public key, where both have the same set of ec
 * domain parameters. if two parties correctly execute this primitive,
 * they will produce the same output. this primitive can be invoked by a
 * scheme to derive a shared secret key; specifically, it may be used
 * with the schemes eckas-dh1 and dl/eckas-dh2. it does not assume the
 * validity of the input public key (see also section 7.2.1).
 * <p>
 * note: as stated p1363 compatibility mode with ecdh can be preset, and
 * in this case the implementation doesn't have a ecdh compatibility mode
 * (if you want that just use ecdhbasicagreement and note they both implement
 * basicagreement!).
 */
public class ecdhcbasicagreement
    implements basicagreement
{
    ecprivatekeyparameters key;

    public void init(
        cipherparameters key)
    {
        this.key = (ecprivatekeyparameters)key;
    }

    public int getfieldsize()
    {
        return (key.getparameters().getcurve().getfieldsize() + 7) / 8;
    }

    public biginteger calculateagreement(
        cipherparameters pubkey)
    {
        ecpublickeyparameters   pub = (ecpublickeyparameters)pubkey;
        ecdomainparameters      params = pub.getparameters();
        ecpoint p = pub.getq().multiply(params.geth().multiply(key.getd()));

        // if (p.isinfinity()) throw new runtimeexception("invalid public key");

        return p.getx().tobiginteger();
    }
}
