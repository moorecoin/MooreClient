package org.ripple.bouncycastle.jce.provider;

import org.ripple.bouncycastle.crypto.datalengthexception;
import org.ripple.bouncycastle.crypto.derivationfunction;
import org.ripple.bouncycastle.crypto.derivationparameters;
import org.ripple.bouncycastle.crypto.digest;
import org.ripple.bouncycastle.crypto.params.kdfparameters;

/**
 * generator for pbe derived keys and ivs as defined by ieee p1363a
 * <br>
 * this implementation is based on draft 9 of ieee p1363a. <b>note:</b>
 * as this is still a draft the output of this generator may change, don't
 * use it for anything that might be subject to long term storage.
 */
public class brokenkdf2bytesgenerator
    implements derivationfunction
{
    private digest  digest;
    private byte[]  shared;
    private byte[]  iv;

    /**
     * construct a kdf2 parameters generator. generates key material
     * according to ieee p1363a - if you want orthodox results you should
     * use a digest specified in the standard.
     * <p>
     * <b>note:</b> ieee p1363a standard is still a draft standard, if the standard
     * changes this function, the output of this function will change as well.
     * don't use this routine for anything subject to long term storage.
     *
     * @param digest the digest to be used as the source of derived keys.
     */
    public brokenkdf2bytesgenerator(
        digest  digest)
    {
        this.digest = digest;
    }

    public void init(
        derivationparameters    param)
    {
        if (!(param instanceof kdfparameters))
        {
            throw new illegalargumentexception("kdf parameters required for kdf2generator");
        }

        kdfparameters   p = (kdfparameters)param;

        shared = p.getsharedsecret();
        iv = p.getiv();
    }

    /**
     * return the underlying digest.
     */
    public digest getdigest()
    {
        return digest;
    }

    /**
     * fill len bytes of the output buffer with bytes generated from
     * the derivation function.
     *
     * @throws illegalargumentexception if the size of the request will cause an overflow.
     * @throws datalengthexception if the out buffer is too small.
     */
    public int generatebytes(
        byte[]  out,
        int     outoff,
        int     len)
        throws datalengthexception, illegalargumentexception
    {
        if ((out.length - len) < outoff)
        {
            throw new datalengthexception("output buffer too small");
        }

        long    obits = len * 8;

        //
        // this is at odds with the standard implementation, the
        // maximum value should be hbits * (2^23 - 1) where hbits
        // is the digest output size in bits. we can't have an
        // array with a long index at the moment...
        //
        if (obits > (digest.getdigestsize() * 8 * (2l^32 - 1)))
        {
            new illegalargumentexception("output length to large");
        }
    
        int cthreshold = (int)(obits / digest.getdigestsize());

        byte[] dig = null;

        dig = new byte[digest.getdigestsize()];

        for (int counter = 1; counter <= cthreshold; counter++)
        {
            digest.update(shared, 0, shared.length);

            digest.update((byte)(counter & 0xff));
            digest.update((byte)((counter >> 8) & 0xff));
            digest.update((byte)((counter >> 16) & 0xff));
            digest.update((byte)((counter >> 24) & 0xff));

            digest.update(iv, 0, iv.length);

            digest.dofinal(dig, 0);

            if ((len - outoff) > dig.length)
            {
                system.arraycopy(dig, 0, out, outoff, dig.length);
                outoff += dig.length;
            }
            else
            {
                system.arraycopy(dig, 0, out, outoff, len - outoff);
            }
        }
    
        digest.reset();

        return len;
    }
}
