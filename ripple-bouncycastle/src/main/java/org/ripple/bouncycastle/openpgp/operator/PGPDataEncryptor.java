package org.ripple.bouncycastle.openpgp.operator;

import java.io.outputstream;

public interface pgpdataencryptor
{
    outputstream getoutputstream(outputstream out);

    pgpdigestcalculator getintegritycalculator();

    int getblocksize();
}
