package org.ripple.bouncycastle.crypto.kems;

import java.math.biginteger;
import java.security.securerandom;

import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.derivationfunction;
import org.ripple.bouncycastle.crypto.keyencapsulation;
import org.ripple.bouncycastle.crypto.params.kdfparameters;
import org.ripple.bouncycastle.crypto.params.keyparameter;
import org.ripple.bouncycastle.crypto.params.rsakeyparameters;
import org.ripple.bouncycastle.util.bigintegers;

/**
 * the rsa key encapsulation mechanism (rsa-kem) from iso 18033-2.
 */
public class rsakeyencapsulation
    implements keyencapsulation
{
    private static final biginteger zero = biginteger.valueof(0);
    private static final biginteger one = biginteger.valueof(1);

    private derivationfunction kdf;
    private securerandom rnd;
    private rsakeyparameters key;

    /**
     * set up the rsa-kem.
     *
     * @param kdf the key derivation function to be used.
     * @param rnd the random source for the session key.
     */
    public rsakeyencapsulation(
        derivationfunction kdf,
        securerandom rnd)
    {
        this.kdf = kdf;
        this.rnd = rnd;
    }


    /**
     * initialise the rsa-kem.
     *
     * @param key the recipient's public (for encryption) or private (for decryption) key.
     */
    public void init(cipherparameters key)
        throws illegalargumentexception
    {
        if (!(key instanceof rsakeyparameters))
        {
            throw new illegalargumentexception("rsa key required");
        }
        else
        {
            this.key = (rsakeyparameters)key;
        }
    }


    /**
     * generate and encapsulate a random session key.
     *
     * @param out    the output buffer for the encapsulated key.
     * @param outoff the offset for the output buffer.
     * @param keylen the length of the random session key.
     * @return the random session key.
     */
    public cipherparameters encrypt(byte[] out, int outoff, int keylen)
        throws illegalargumentexception
    {
        if (key.isprivate())
        {
            throw new illegalargumentexception("public key required for encryption");
        }

        biginteger n = key.getmodulus();
        biginteger e = key.getexponent();

        // generate the ephemeral random and encode it    
        biginteger r = bigintegers.createrandominrange(zero, n.subtract(one), rnd);
        byte[] r = bigintegers.asunsignedbytearray((n.bitlength() + 7) / 8, r);

        // encrypt the random and encode it     
        biginteger c = r.modpow(e, n);
        byte[] c = bigintegers.asunsignedbytearray((n.bitlength() + 7) / 8, c);
        system.arraycopy(c, 0, out, outoff, c.length);


        // initialise the kdf
        kdf.init(new kdfparameters(r, null));

        // generate the secret key
        byte[] k = new byte[keylen];
        kdf.generatebytes(k, 0, k.length);

        return new keyparameter(k);
    }


    /**
     * generate and encapsulate a random session key.
     *
     * @param out    the output buffer for the encapsulated key.
     * @param keylen the length of the random session key.
     * @return the random session key.
     */
    public cipherparameters encrypt(byte[] out, int keylen)
    {
        return encrypt(out, 0, keylen);
    }


    /**
     * decrypt an encapsulated session key.
     *
     * @param in     the input buffer for the encapsulated key.
     * @param inoff  the offset for the input buffer.
     * @param inlen  the length of the encapsulated key.
     * @param keylen the length of the session key.
     * @return the session key.
     */
    public cipherparameters decrypt(byte[] in, int inoff, int inlen, int keylen)
        throws illegalargumentexception
    {
        if (!key.isprivate())
        {
            throw new illegalargumentexception("private key required for decryption");
        }

        biginteger n = key.getmodulus();
        biginteger d = key.getexponent();

        // decode the input
        byte[] c = new byte[inlen];
        system.arraycopy(in, inoff, c, 0, c.length);
        biginteger c = new biginteger(1, c);

        // decrypt the ephemeral random and encode it
        biginteger r = c.modpow(d, n);
        byte[] r = bigintegers.asunsignedbytearray((n.bitlength() + 7) / 8, r);

        // initialise the kdf
        kdf.init(new kdfparameters(r, null));

        // generate the secret key
        byte[] k = new byte[keylen];
        kdf.generatebytes(k, 0, k.length);

        return new keyparameter(k);
    }

    /**
     * decrypt an encapsulated session key.
     *
     * @param in     the input buffer for the encapsulated key.
     * @param keylen the length of the session key.
     * @return the session key.
     */
    public cipherparameters decrypt(byte[] in, int keylen)
    {
        return decrypt(in, 0, in.length, keylen);
    }
}
