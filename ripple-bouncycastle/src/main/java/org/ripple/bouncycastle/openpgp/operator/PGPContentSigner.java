package org.ripple.bouncycastle.openpgp.operator;

import java.io.outputstream;

public interface pgpcontentsigner
{
    public outputstream getoutputstream();

    byte[] getsignature();

    byte[] getdigest();

    int gettype();

    int gethashalgorithm();

    int getkeyalgorithm();

    long getkeyid();
}
