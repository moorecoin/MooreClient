package org.ripple.bouncycastle.crypto.ec;

import org.ripple.bouncycastle.crypto.cipherparameters;

public interface ecpairtransform
{
    void init(cipherparameters params);

    ecpair transform(ecpair ciphertext);
}
