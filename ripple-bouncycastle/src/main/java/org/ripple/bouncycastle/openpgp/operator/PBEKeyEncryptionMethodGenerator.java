package org.ripple.bouncycastle.openpgp.operator;

import java.security.securerandom;

import org.ripple.bouncycastle.bcpg.containedpacket;
import org.ripple.bouncycastle.bcpg.s2k;
import org.ripple.bouncycastle.bcpg.symmetrickeyencsessionpacket;
import org.ripple.bouncycastle.openpgp.pgpexception;

public abstract class pbekeyencryptionmethodgenerator
    extends pgpkeyencryptionmethodgenerator
{
    private char[] passphrase;
    private pgpdigestcalculator s2kdigestcalculator;
    private s2k s2k;
    private securerandom random;
    private int s2kcount;

    protected pbekeyencryptionmethodgenerator(
        char[] passphrase,
        pgpdigestcalculator s2kdigestcalculator)
    {
        this(passphrase, s2kdigestcalculator, 0x60);
    }

    protected pbekeyencryptionmethodgenerator(
        char[] passphrase,
        pgpdigestcalculator s2kdigestcalculator,
        int s2kcount)
    {
        this.passphrase = passphrase;
        this.s2kdigestcalculator = s2kdigestcalculator;

        if (s2kcount < 0 || s2kcount > 0xff)
        {
            throw new illegalargumentexception("s2kcount value outside of range 0 to 255.");
        }

        this.s2kcount = s2kcount;
    }

    public pbekeyencryptionmethodgenerator setsecurerandom(securerandom random)
    {
        this.random = random;

        return this;
    }

    public byte[] getkey(int encalgorithm)
        throws pgpexception
    {
        if (s2k == null)
        {
            byte[]        iv = new byte[8];

            if (random == null)
            {
                random = new securerandom();
            }

            random.nextbytes(iv);

            s2k = new s2k(s2kdigestcalculator.getalgorithm(), iv, s2kcount);
        }

        return pgputil.makekeyfrompassphrase(s2kdigestcalculator, encalgorithm, s2k, passphrase);
    }

    public containedpacket generate(int encalgorithm, byte[] sessioninfo)
        throws pgpexception
    {
        byte[] key = getkey(encalgorithm);

        if (sessioninfo == null)
        {
            return new symmetrickeyencsessionpacket(encalgorithm, s2k, null);
        }

        //
        // the passed in session info has the an rsa/elgamal checksum added to it, for pbe this is not included.
        //
        byte[] nsessioninfo = new byte[sessioninfo.length - 2];

        system.arraycopy(sessioninfo, 0, nsessioninfo, 0, nsessioninfo.length);

        return new symmetrickeyencsessionpacket(encalgorithm, s2k, encryptsessioninfo(encalgorithm, key, nsessioninfo));
    }

    abstract protected byte[]  encryptsessioninfo(int encalgorithm, byte[] key, byte[] sessioninfo)
        throws pgpexception;
}
