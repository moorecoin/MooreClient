package org.ripple.bouncycastle.crypto;

import java.io.ioexception;
import java.io.inputstream;

import org.ripple.bouncycastle.crypto.params.asymmetrickeyparameter;

public interface keyparser
{
    asymmetrickeyparameter readkey(inputstream stream)
        throws ioexception;
}
