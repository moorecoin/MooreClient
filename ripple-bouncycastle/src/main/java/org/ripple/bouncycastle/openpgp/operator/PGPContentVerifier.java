package org.ripple.bouncycastle.openpgp.operator;

import java.io.outputstream;

public interface pgpcontentverifier
{
    public outputstream getoutputstream();

    int gethashalgorithm();

    int getkeyalgorithm();

    long getkeyid();

    /**
     * @param expected expected value of the signature on the data.
     * @return true if the signature verifies, false otherwise
     */
    boolean verify(byte[] expected);
}
