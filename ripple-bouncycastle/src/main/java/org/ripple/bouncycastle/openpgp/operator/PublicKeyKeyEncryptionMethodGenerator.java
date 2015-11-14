package org.ripple.bouncycastle.openpgp.operator;

import java.math.biginteger;

import org.ripple.bouncycastle.bcpg.containedpacket;
import org.ripple.bouncycastle.bcpg.publickeyencsessionpacket;
import org.ripple.bouncycastle.openpgp.pgpexception;
import org.ripple.bouncycastle.openpgp.pgppublickey;

public abstract class publickeykeyencryptionmethodgenerator
    extends pgpkeyencryptionmethodgenerator
{
    private pgppublickey pubkey;

    protected publickeykeyencryptionmethodgenerator(
        pgppublickey pubkey)
    {
        this.pubkey = pubkey;

        switch (pubkey.getalgorithm())
        {
            case pgppublickey.rsa_encrypt:
            case pgppublickey.rsa_general:
                break;
            case pgppublickey.elgamal_encrypt:
            case pgppublickey.elgamal_general:
                break;
            case pgppublickey.dsa:
                throw new illegalargumentexception("can't use dsa for encryption.");
            case pgppublickey.ecdsa:
                throw new illegalargumentexception("can't use ecdsa for encryption.");
            default:
                throw new illegalargumentexception("unknown asymmetric algorithm: " + pubkey.getalgorithm());
        }
    }

    public biginteger[] processsessioninfo(
        byte[] encryptedsessioninfo)
        throws pgpexception
    {
        biginteger[] data;

        switch (pubkey.getalgorithm())
        {
            case pgppublickey.rsa_encrypt:
            case pgppublickey.rsa_general:
                data = new biginteger[1];

                data[0] = new biginteger(1, encryptedsessioninfo);
                break;
            case pgppublickey.elgamal_encrypt:
            case pgppublickey.elgamal_general:
                byte[] b1 = new byte[encryptedsessioninfo.length / 2];
                byte[] b2 = new byte[encryptedsessioninfo.length / 2];

                system.arraycopy(encryptedsessioninfo, 0, b1, 0, b1.length);
                system.arraycopy(encryptedsessioninfo, b1.length, b2, 0, b2.length);

                data = new biginteger[2];
                data[0] = new biginteger(1, b1);
                data[1] = new biginteger(1, b2);
                break;
            default:
                throw new pgpexception("unknown asymmetric algorithm: " + pubkey.getalgorithm());
        }

        return data;
    }

    public containedpacket generate(int encalgorithm, byte[] sessioninfo)
        throws pgpexception
    {
        return new publickeyencsessionpacket(pubkey.getkeyid(), pubkey.getalgorithm(), processsessioninfo(encryptsessioninfo(pubkey, sessioninfo)));
    }

    abstract protected byte[] encryptsessioninfo(pgppublickey pubkey, byte[] sessioninfo)
        throws pgpexception;
}
