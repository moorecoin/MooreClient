package org.ripple.bouncycastle.openpgp.operator;

import java.io.inputstream;

public interface pgpdatadecryptor
{
    inputstream getinputstream(inputstream in);

    int getblocksize();

    pgpdigestcalculator getintegritycalculator();
}
