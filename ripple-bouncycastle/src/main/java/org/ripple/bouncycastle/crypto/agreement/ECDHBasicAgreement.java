package org.ripple.bouncycastle.crypto.agreement;

import java.math.biginteger;

import org.ripple.bouncycastle.crypto.basicagreement;
import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.params.ecprivatekeyparameters;
import org.ripple.bouncycastle.crypto.params.ecpublickeyparameters;
import org.ripple.bouncycastle.math.ec.ecpoint;

/**
 * p1363 7.2.1 ecsvdp-dh
 *
 * ecsvdp-dh is elliptic curve secret value derivation primitive,
 * diffie-hellman version. it is based on the work of [dh76], [mil86],
 * and [kob87]. this primitive derives a shared secret value from one
 * party's private key and another party's public key, where both have
 * the same set of ec domain parameters. if two parties correctly
 * execute this primitive, they will produce the same output. this
 * primitive can be invoked by a scheme to derive a shared secret key;
 * specifically, it may be used with the schemes eckas-dh1 and
 * dl/eckas-dh2. it assumes that the input keys are valid (see also
 * section 7.2.2).
 */
public class ecdhbasicagreement
    implements basicagreement
{
    private ecprivatekeyparameters key;

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
        ecpublickeyparameters pub = (ecpublickeyparameters)pubkey;
        ecpoint p = pub.getq().multiply(key.getd());

        // if (p.isinfinity()) throw new runtimeexception("d*q == infinity");

        return p.getx().tobiginteger();
    }
}
