package org.ripple.bouncycastle.crypto.agreement.kdf;

import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.derobjectidentifier;
import org.ripple.bouncycastle.crypto.derivationparameters;

public class dhkdfparameters
    implements derivationparameters
{
    private asn1objectidentifier algorithm;
    private int keysize;
    private byte[] z;
    private byte[] extrainfo;

    public dhkdfparameters(
        derobjectidentifier algorithm,
        int keysize,
        byte[] z)
    {
        this(algorithm, keysize, z, null);
    }

    public dhkdfparameters(
        derobjectidentifier algorithm,
        int keysize,
        byte[] z,
        byte[] extrainfo)
    {
        this.algorithm = new asn1objectidentifier(algorithm.getid());
        this.keysize = keysize;
        this.z = z;
        this.extrainfo = extrainfo;
    }

    public asn1objectidentifier getalgorithm()
    {
        return algorithm;
    }

    public int getkeysize()
    {
        return keysize;
    }

    public byte[] getz()
    {
        return z;
    }

    public byte[] getextrainfo()
    {
        return extrainfo;
    }
}
