package org.ripple.bouncycastle.crypto.ec;

import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.math.ec.ecpoint;

public interface ecencryptor
{
    void init(cipherparameters params);

    ecpair encrypt(ecpoint point);
}
