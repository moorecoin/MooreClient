package org.ripple.bouncycastle.openpgp.operator.jcajce;

import java.io.ioexception;
import java.security.messagedigest;
import java.security.nosuchalgorithmexception;

import org.ripple.bouncycastle.bcpg.bcpgkey;
import org.ripple.bouncycastle.bcpg.mpinteger;
import org.ripple.bouncycastle.bcpg.publickeypacket;
import org.ripple.bouncycastle.bcpg.rsapublicbcpgkey;
import org.ripple.bouncycastle.openpgp.pgpexception;
import org.ripple.bouncycastle.openpgp.operator.keyfingerprintcalculator;

public class jcakeyfingerprintcalculator
    implements keyfingerprintcalculator
{
    public byte[] calculatefingerprint(publickeypacket publicpk)
        throws pgpexception
    {
        bcpgkey key = publicpk.getkey();

        if (publicpk.getversion() <= 3)
        {
            rsapublicbcpgkey rk = (rsapublicbcpgkey)key;

            try
            {
                messagedigest digest = messagedigest.getinstance("md5");

                byte[]  bytes = new mpinteger(rk.getmodulus()).getencoded();
                digest.update(bytes, 2, bytes.length - 2);

                bytes = new mpinteger(rk.getpublicexponent()).getencoded();
                digest.update(bytes, 2, bytes.length - 2);

                return digest.digest();
            }
            catch (nosuchalgorithmexception e)
            {
                throw new pgpexception("can't find md5", e);
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

                messagedigest   digest = messagedigest.getinstance("sha1");

                digest.update((byte)0x99);
                digest.update((byte)(kbytes.length >> 8));
                digest.update((byte)kbytes.length);
                digest.update(kbytes);

                return digest.digest();
            }
            catch (nosuchalgorithmexception e)
            {
                throw new pgpexception("can't find sha1", e);
            }
            catch (ioexception e)
            {
                throw new pgpexception("can't encode key components: " + e.getmessage(), e);
            }
        }
    }
}
