package org.ripple.bouncycastle.openpgp.operator.bc;

import java.io.ioexception;

import org.ripple.bouncycastle.bcpg.bcpgkey;
import org.ripple.bouncycastle.bcpg.mpinteger;
import org.ripple.bouncycastle.bcpg.publickeypacket;
import org.ripple.bouncycastle.bcpg.rsapublicbcpgkey;
import org.ripple.bouncycastle.crypto.digest;
import org.ripple.bouncycastle.crypto.digests.md5digest;
import org.ripple.bouncycastle.crypto.digests.sha1digest;
import org.ripple.bouncycastle.openpgp.pgpexception;
import org.ripple.bouncycastle.openpgp.operator.keyfingerprintcalculator;

public class bckeyfingerprintcalculator
    implements keyfingerprintcalculator
{
    public byte[] calculatefingerprint(publickeypacket publicpk)
        throws pgpexception
    {
        bcpgkey key = publicpk.getkey();
        digest digest;

        if (publicpk.getversion() <= 3)
        {
            rsapublicbcpgkey rk = (rsapublicbcpgkey)key;

            try
            {
                digest = new md5digest();

                byte[]  bytes = new mpinteger(rk.getmodulus()).getencoded();
                digest.update(bytes, 2, bytes.length - 2);

                bytes = new mpinteger(rk.getpublicexponent()).getencoded();
                digest.update(bytes, 2, bytes.length - 2);
            }
            catch (ioexception e)
            {
                throw new pgpexception("can't encode key components: " + e.getmessage(), e);
            }
        }
        else
        {
            try
            {
                byte[]             kbytes = publicpk.getencodedcontents();

                digest = new sha1digest();

                digest.update((byte)0x99);
                digest.update((byte)(kbytes.length >> 8));
                digest.update((byte)kbytes.length);
                digest.update(kbytes, 0, kbytes.length);
            }
            catch (ioexception e)
            {
                throw new pgpexception("can't encode key components: " + e.getmessage(), e);
            }
        }

        byte[] digbuf = new byte[digest.getdigestsize()];

        digest.dofinal(digbuf, 0);

        return digbuf;
    }
}
