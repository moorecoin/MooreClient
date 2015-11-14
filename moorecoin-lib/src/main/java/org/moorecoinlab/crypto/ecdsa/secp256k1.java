package org.moorecoinlab.crypto.ecdsa;

import org.ripple.bouncycastle.asn1.sec.secnamedcurves;
import org.ripple.bouncycastle.asn1.x9.x9ecparameters;
import org.ripple.bouncycastle.crypto.params.ecdomainparameters;
import org.ripple.bouncycastle.math.ec.eccurve;
import org.ripple.bouncycastle.math.ec.ecpoint;

import java.math.biginteger;

public class secp256k1 {
    private static final ecdomainparameters ecparams;
    private static final x9ecparameters params;

    static {

        params = secnamedcurves.getbyname("secp256k1");
        ecparams = new ecdomainparameters(params.getcurve(), params.getg(), params.getn(), params.geth());
    }

    public static ecdomainparameters params() {
        return ecparams;
    }

    public static biginteger order() {
        return ecparams.getn();
    }


    public static eccurve curve() {
        return ecparams.getcurve();
    }

    public static ecpoint basepoint() {
        return ecparams.getg();
    }

    static byte[] basepointmultipliedby(biginteger secret) {
        return basepoint().multiply(secret).getencoded(true);
    }
}
