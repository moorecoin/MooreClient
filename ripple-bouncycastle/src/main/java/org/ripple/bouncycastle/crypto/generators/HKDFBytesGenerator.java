package org.ripple.bouncycastle.crypto.generators;

import org.ripple.bouncycastle.crypto.datalengthexception;
import org.ripple.bouncycastle.crypto.derivationfunction;
import org.ripple.bouncycastle.crypto.derivationparameters;
import org.ripple.bouncycastle.crypto.digest;
import org.ripple.bouncycastle.crypto.macs.hmac;
import org.ripple.bouncycastle.crypto.params.hkdfparameters;
import org.ripple.bouncycastle.crypto.params.keyparameter;

/**
 * hmac-based extract-and-expand key derivation function (hkdf) implemented
 * according to ietf rfc 5869, may 2010 as specified by h. krawczyk, ibm
 * research & p. eronen, nokia. it uses a hmac internally to compute de okm
 * (output keying material) and is likely to have better security properties
 * than kdf's based on just a hash function.
 */
public class hkdfbytesgenerator
    implements derivationfunction
{

    private hmac hmachash;
    private int hashlen;

    private byte[] info;
    private byte[] currentt;

    private int generatedbytes;

    /**
     * creates a hkdfbytesgenerator based on the given hash function.
     *
     * @param hash the digest to be used as the source of generatedbytes bytes
     */
    public hkdfbytesgenerator(digest hash)
    {
        this.hmachash = new hmac(hash);
        this.hashlen = hash.getdigestsize();
    }

    public void init(derivationparameters param)
    {
        if (!(param instanceof hkdfparameters))
        {
            throw new illegalargumentexception(
                "hkdf parameters required for hkdfbytesgenerator");
        }

        hkdfparameters params = (hkdfparameters)param;
        if (params.skipextract())
        {
            // use ikm directly as prk
            hmachash.init(new keyparameter(params.getikm()));
        }
        else
        {
            hmachash.init(extract(params.getsalt(), params.getikm()));
        }

        info = params.getinfo();

        generatedbytes = 0;
        currentt = new byte[hashlen];
    }

    /**
     * performs the extract part of the key derivation function.
     *
     * @param salt the salt to use
     * @param ikm  the input keying material
     * @return the prk as keyparameter
     */
    private keyparameter extract(byte[] salt, byte[] ikm)
    {
        hmachash.init(new keyparameter(ikm));
        if (salt == null)
        {
            // todo check if hashlen is indeed same as hmac size
            hmachash.init(new keyparameter(new byte[hashlen]));
        }
        else
        {
            hmachash.init(new keyparameter(salt));
        }

        hmachash.update(ikm, 0, ikm.length);

        byte[] prk = new byte[hashlen];
        hmachash.dofinal(prk, 0);
        return new keyparameter(prk);
    }

    /**
     * performs the expand part of the key derivation function, using currentt
     * as input and output buffer.
     *
     * @throws datalengthexception if the total number of bytes generated is larger than the one
     * specified by rfc 5869 (255 * hashlen)
     */
    private void expandnext()
        throws datalengthexception
    {
        int n = generatedbytes / hashlen + 1;
        if (n >= 256)
        {
            throw new datalengthexception(
                "hkdf cannot generate more than 255 blocks of hashlen size");
        }
        // special case for t(0): t(0) is empty, so no update
        if (generatedbytes != 0)
        {
            hmachash.update(currentt, 0, hashlen);
        }
        hmachash.update(info, 0, info.length);
        hmachash.update((byte)n);
        hmachash.dofinal(currentt, 0);
    }

    public digest getdigest()
    {
        return hmachash.getunderlyingdigest();
    }

    public int generatebytes(byte[] out, int outoff, int len)
        throws datalengthexception, illegalargumentexception
    {

        if (generatedbytes + len > 255 * hashlen)
        {
            throw new datalengthexception(
                "hkdf may only be used for 255 * hashlen bytes of output");
        }

        if (generatedbytes % hashlen == 0)
        {
            expandnext();
        }

        // copy what is left in the currentt (1..hash
        int togenerate = len;
        int posint = generatedbytes % hashlen;
        int leftint = hashlen - generatedbytes % hashlen;
        int tocopy = math.min(leftint, togenerate);
        system.arraycopy(currentt, posint, out, outoff, tocopy);
        generatedbytes += tocopy;
        togenerate -= tocopy;
        outoff += tocopy;

        while (togenerate > 0)
        {
            expandnext();
            tocopy = math.min(hashlen, togenerate);
            system.arraycopy(currentt, 0, out, outoff, tocopy);
            generatedbytes += tocopy;
            togenerate -= tocopy;
            outoff += tocopy;
        }

        return len;
    }
}
