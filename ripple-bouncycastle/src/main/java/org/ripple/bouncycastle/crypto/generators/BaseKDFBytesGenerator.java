package org.ripple.bouncycastle.crypto.generators;

import org.ripple.bouncycastle.crypto.datalengthexception;
import org.ripple.bouncycastle.crypto.derivationfunction;
import org.ripple.bouncycastle.crypto.derivationparameters;
import org.ripple.bouncycastle.crypto.digest;
import org.ripple.bouncycastle.crypto.params.iso18033kdfparameters;
import org.ripple.bouncycastle.crypto.params.kdfparameters;
import org.ripple.bouncycastle.crypto.util.pack;

/**
 * basic kdf generator for derived keys and ivs as defined by ieee p1363a/iso
 * 18033 <br>
 * this implementation is based on iso 18033/p1363a.
 */
public class basekdfbytesgenerator implements derivationfunction
{
    private int    counterstart;
    private digest digest;
    private byte[] shared;
    private byte[] iv;

    /**
     * construct a kdf parameters generator.
     * <p>
     * 
     * @param counterstart
     *            value of counter.
     * @param digest
     *            the digest to be used as the source of derived keys.
     */
    protected basekdfbytesgenerator(int counterstart, digest digest)
    {
        this.counterstart = counterstart;
        this.digest = digest;
    }

    public void init(derivationparameters param)
    {
        if (param instanceof kdfparameters)
        {
            kdfparameters p = (kdfparameters)param;

            shared = p.getsharedsecret();
            iv = p.getiv();
        }
        else if (param instanceof iso18033kdfparameters)
        {
            iso18033kdfparameters p = (iso18033kdfparameters)param;

            shared = p.getseed();
            iv = null;
        }
        else
        {
            throw new illegalargumentexception("kdf parameters required for kdf2generator");
        }
    }

    /**
     * return the underlying digest.
     */
    public digest getdigest()
    {
        return digest;
    }

    /**
     * fill len bytes of the output buffer with bytes generated from the
     * derivation function.
     * 
     * @throws illegalargumentexception
     *             if the size of the request will cause an overflow.
     * @throws datalengthexception
     *             if the out buffer is too small.
     */
    public int generatebytes(byte[] out, int outoff, int len) throws datalengthexception,
            illegalargumentexception
    {
        if ((out.length - len) < outoff)
        {
            throw new datalengthexception("output buffer too small");
        }

        long obytes = len;
        int outlen = digest.getdigestsize();

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

        byte[] c = new byte[4];
        pack.inttobigendian(counterstart, c, 0);

        int counterbase = counterstart & ~0xff;

        for (int i = 0; i < cthreshold; i++)
        {
            digest.update(shared, 0, shared.length);
            digest.update(c, 0, c.length);

            if (iv != null)
            {
                digest.update(iv, 0, iv.length);
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

            if (++c[3] == 0)
            {
                counterbase += 0x100;
                pack.inttobigendian(counterbase, c, 0);
            }
        }

        digest.reset();

        return (int)obytes;
    }
}
