package org.ripple.bouncycastle.crypto.ec;

import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.math.ec.ecpoint;

public interface ecdecryptor
{
    void init(cipherparameters params);

    ecpoint decrypt(ecpair ciphertext);
}
