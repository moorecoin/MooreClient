package org.ripple.bouncycastle.crypto;

import org.ripple.bouncycastle.crypto.params.asymmetrickeyparameter;

public interface keyencoder
{
    byte[] getencoded(asymmetrickeyparameter keyparameter);
}
