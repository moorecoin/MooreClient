package org.ripple.bouncycastle.crypto.kems;

import java.math.biginteger;
import java.security.securerandom;

import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.derivationfunction;
import org.ripple.bouncycastle.crypto.keyencapsulation;
import org.ripple.bouncycastle.crypto.params.eckeyparameters;
import org.ripple.bouncycastle.crypto.params.ecprivatekeyparameters;
import org.ripple.bouncycastle.crypto.params.ecpublickeyparameters;
import org.ripple.bouncycastle.crypto.params.kdfparameters;
import org.ripple.bouncycastle.crypto.params.keyparameter;
import org.ripple.bouncycastle.math.ec.ecpoint;
import org.ripple.bouncycastle.util.bigintegers;

/**
 * the ecies key encapsulation mechanism (ecies-kem) from iso 18033-2.
 */
public class ecieskeyencapsulation
    implements keyencapsulation
{
    private static final biginteger one = biginteger.valueof(1);

    private derivationfunction kdf;
    private securerandom rnd;
    private eckeyparameters key;
    private boolean cofactormode;
    private boolean oldcofactormode;
    private boolean singlehashmode;

    /**
     * set up the ecies-kem.
     *
     * @param kdf the key derivation function to be used.
     * @param rnd the random source for the session key.
     */
    public ecieskeyencapsulation(
        derivationfunction kdf,
        securerandom rnd)
    {
        this.kdf = kdf;
        this.rnd = rnd;
        this.cofactormode = false;
        this.oldcofactormode = false;
        this.singlehashmode = false;
    }

    /**
     * set up the ecies-kem.
     *
     * @param kdf             the key derivation function to be used.
     * @param rnd             the random source for the session key.
     * @param cofactormode    true to use the new cofactor ecdh.
     * @param oldcofactormode true to use the old cofactor ecdh.
     * @param singlehashmode  true to use single hash mode.
     */
    public ecieskeyencapsulation(
        derivationfunction kdf,
        securerandom rnd,
        boolean cofactormode,
        boolean oldcofactormode,
        boolean singlehashmode)
    {
        this.kdf = kdf;
        this.rnd = rnd;

        // if both cofactormode and oldcofactormode are set to true
        // then the implementation will use the new cofactor ecdh 
        this.cofactormode = cofactormode;
        this.oldcofactormode = oldcofactormode;
        this.singlehashmode = singlehashmode;
    }

    /**
     * initialise the ecies-kem.
     *
     * @param key the recipient's public (for encryption) or private (for decryption) key.
     */
    public void init(cipherparameters key)
        throws illegalargumentexception
    {
        if (!(key instanceof eckeyparameters))
        {
            throw new illegalargumentexception("ec key required");
        }
        else
        {
            this.key = (eckeyparameters)key;
        }
    }

    /**
     * generate and encapsulate a random session key.
     *
     * @param out    the output buffer for the encapsulated key.
     * @param outoff the offset for the output buffer.
     * @param keylen the length of the session key.
     * @return the random session key.
     */
    public cipherparameters encrypt(byte[] out, int outoff, int keylen)
        throws illegalargumentexception
    {
        if (!(key instanceof ecpublickeyparameters))
        {
            throw new illegalargumentexception("public key required for encryption");
        }

        biginteger n = key.getparameters().getn();
        biginteger h = key.getparameters().geth();

        // generate the ephemeral key pair    
        biginteger r = bigintegers.createrandominrange(one, n, rnd);
        ecpoint gtilde = key.getparameters().getg().multiply(r);

        // encode the ephemeral public key
        byte[] c = gtilde.getencoded();
        system.arraycopy(c, 0, out, outoff, c.length);

        // compute the static-ephemeral key agreement
        biginteger rprime;
        if (cofactormode)
        {
            rprime = r.multiply(h).mod(n);
        }
        else
        {
            rprime = r;
        }

        ecpoint htilde = ((ecpublickeyparameters)key).getq().multiply(rprime);

        // encode the shared secret value
        int pehlen = (key.getparameters().getcurve().getfieldsize() + 7) / 8;
        byte[] peh = bigintegers.asunsignedbytearray(pehlen, htilde.getx().tobiginteger());

        // initialise the kdf
        byte[] kdfinput;
        if (singlehashmode)
        {
            kdfinput = new byte[c.length + peh.length];
            system.arraycopy(c, 0, kdfinput, 0, c.length);
            system.arraycopy(peh, 0, kdfinput, c.length, peh.length);
        }
        else
        {
            kdfinput = peh;
        }

        kdf.init(new kdfparameters(kdfinput, null));

        // generate the secret key
        byte[] k = new byte[keylen];
        kdf.generatebytes(k, 0, k.length);

        // return the ciphertext
        return new keyparameter(k);
    }

    /**
     * generate and encapsulate a random session key.
     *
     * @param out    the output buffer for the encapsulated key.
     * @param keylen the length of the session key.
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
        if (!(key instanceof ecprivatekeyparameters))
        {
            throw new illegalargumentexception("private key required for encryption");
        }

        biginteger n = key.getparameters().getn();
        biginteger h = key.getparameters().geth();

        // decode the ephemeral public key
        byte[] c = new byte[inlen];
        system.arraycopy(in, inoff, c, 0, inlen);
        ecpoint gtilde = key.getparameters().getcurve().decodepoint(c);

        // compute the static-ephemeral key agreement
        ecpoint ghat;
        if ((cofactormode) || (oldcofactormode))
        {
            ghat = gtilde.multiply(h);
        }
        else
        {
            ghat = gtilde;
        }

        biginteger xhat;
        if (cofactormode)
        {
            xhat = ((ecprivatekeyparameters)key).getd().multiply(h.modinverse(n)).mod(n);
        }
        else
        {
            xhat = ((ecprivatekeyparameters)key).getd();
        }

        ecpoint htilde = ghat.multiply(xhat);

        // encode the shared secret value
        int pehlen = (key.getparameters().getcurve().getfieldsize() + 7) / 8;
        byte[] peh = bigintegers.asunsignedbytearray(pehlen, htilde.getx().tobiginteger());

        // initialise the kdf
        byte[] kdfinput;
        if (singlehashmode)
        {
            kdfinput = new byte[c.length + peh.length];
            system.arraycopy(c, 0, kdfinput, 0, c.length);
            system.arraycopy(peh, 0, kdfinput, c.length, peh.length);
        }
        else
        {
            kdfinput = peh;
        }
        kdf.init(new kdfparameters(kdfinput, null));

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
