package org.ripple.bouncycastle.crypto.agreement.kdf;

import java.io.ioexception;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1encoding;
import org.ripple.bouncycastle.asn1.derobjectidentifier;
import org.ripple.bouncycastle.asn1.deroctetstring;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.dertaggedobject;
import org.ripple.bouncycastle.crypto.datalengthexception;
import org.ripple.bouncycastle.crypto.derivationfunction;
import org.ripple.bouncycastle.crypto.derivationparameters;
import org.ripple.bouncycastle.crypto.digest;
import org.ripple.bouncycastle.crypto.util.pack;

/**
 * rfc 2631 diffie-hellman kek derivation function.
 */
public class dhkekgenerator
    implements derivationfunction
{
    private final digest digest;

    private derobjectidentifier algorithm;
    private int                 keysize;
    private byte[]              z;
    private byte[]              partyainfo;

    public dhkekgenerator(
        digest digest)
    {
        this.digest = digest;
    }

    public void init(derivationparameters param)
    {
        dhkdfparameters params = (dhkdfparameters)param;

        this.algorithm = params.getalgorithm();
        this.keysize = params.getkeysize();
        this.z = params.getz();
        this.partyainfo = params.getextrainfo();
    }

    public digest getdigest()
    {
        return digest;
    }

    public int generatebytes(byte[] out, int outoff, int len)
        throws datalengthexception, illegalargumentexception
    {
        if ((out.length - len) < outoff)
        {
            throw new datalengthexception("output buffer too small");
        }

        long    obytes = len;
        int     outlen = digest.getdigestsize();

        //
        // this is at odds with the standard implementation, the
        // maximum value should be hbits * (2^32 - 1) where hbits
        // is the digest output size in bits. we can't have an
        // array with a long index at the moment...
        //
        if (obytes > ((2l << 32) - 1))
        {
            throw new illegalargumentexception("output length too large");
        }

        int cthreshold = (int)((obytes + outlen - 1) / outlen);

        byte[] dig = new byte[digest.getdigestsize()];

        int counter = 1;

        for (int i = 0; i < cthreshold; i++)
        {
            digest.update(z, 0, z.length);

            // otherinfo
            asn1encodablevector v1 = new asn1encodablevector();
            // keyspecificinfo
            asn1encodablevector v2 = new asn1encodablevector();

            v2.add(algorithm);
            v2.add(new deroctetstring(pack.inttobigendian(counter)));

            v1.add(new dersequence(v2));

            if (partyainfo != null)
            {
                v1.add(new dertaggedobject(true, 0, new deroctetstring(partyainfo)));
            }

            v1.add(new dertaggedobject(true, 2, new deroctetstring(pack.inttobigendian(keysize))));

            try
            {
                byte[] other = new dersequence(v1).getencoded(asn1encoding.der);

                digest.update(other, 0, other.length);
            }
            catch (ioexception e)
            {
                throw new illegalargumentexception("unable to encode parameter info: " + e.getmessage());
            }

            digest.dofinal(dig, 0);

            if (len > outlen)
            {
                system.arraycopy(dig, 0, out, outoff, outlen);
                outoff += outlen;
                len -= outlen;
            }
            else
            {
                system.arraycopy(dig, 0, out, outoff, len);
            }

            counter++;
        }

        digest.reset();

        return (int)obytes;
    }
}
