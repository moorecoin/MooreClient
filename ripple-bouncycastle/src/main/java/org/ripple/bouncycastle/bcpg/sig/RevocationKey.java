package org.ripple.bouncycastle.bcpg.sig;

import org.ripple.bouncycastle.bcpg.signaturesubpacket;
import org.ripple.bouncycastle.bcpg.signaturesubpackettags;

/**
 * represents revocation key openpgp signature sub packet.
 */
public class revocationkey extends signaturesubpacket
{
    // 1 octet of class, 
    // 1 octet of public-key algorithm id, 
    // 20 octets of fingerprint
    public revocationkey(boolean iscritical, byte[] data)
    {
        super(signaturesubpackettags.revocation_key, iscritical, data);
    }

    public revocationkey(boolean iscritical, byte signatureclass, int keyalgorithm,
        byte[] fingerprint)
    {
        super(signaturesubpackettags.revocation_key, iscritical, createdata(signatureclass,
            (byte)(keyalgorithm & 0xff), fingerprint));
    }

    private static byte[] createdata(byte signatureclass, byte keyalgorithm, byte[] fingerprint)
    {
        byte[] data = new byte[2 + fingerprint.length];
        data[0] = signatureclass;
        data[1] = keyalgorithm;
        system.arraycopy(fingerprint, 0, data, 2, fingerprint.length);
        return data;
    }

    public byte getsignatureclass()
    {
        return this.getdata()[0];
    }

    public int getalgorithm()
    {
        return this.getdata()[1];
    }

    public byte[] getfingerprint()
    {
        byte[] data = this.getdata();
        byte[] fingerprint = new byte[data.length - 2];
        system.arraycopy(data, 2, fingerprint, 0, fingerprint.length);
        return fingerprint;
    }
}
