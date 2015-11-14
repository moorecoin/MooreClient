package org.ripple.bouncycastle.pqc.crypto.mceliece;

import java.security.securerandom;

import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.digest;
import org.ripple.bouncycastle.crypto.digests.sha1digest;
import org.ripple.bouncycastle.crypto.params.parameterswithrandom;
import org.ripple.bouncycastle.crypto.prng.digestrandomgenerator;
import org.ripple.bouncycastle.pqc.crypto.messageencryptor;
import org.ripple.bouncycastle.pqc.math.linearalgebra.byteutils;
import org.ripple.bouncycastle.pqc.math.linearalgebra.gf2vector;

/**
 * this class implements the fujisaki/okamoto conversion of the mceliecepkcs.
 * fujisaki and okamoto propose hybrid encryption that merges a symmetric
 * encryption scheme which is secure in the find-guess model with an asymmetric
 * one-way encryption scheme which is sufficiently probabilistic to obtain a
 * public key cryptosystem which is cca2-secure. for details, see d. engelbert,
 * r. overbeck, a. schmidt, "a summary of the development of the mceliece
 * cryptosystem", technical report.
 */
public class mceliecefujisakicipher
    implements messageencryptor
{


    /**
     * the oid of the algorithm.
     */
    public static final string oid = "1.3.6.1.4.1.8301.3.1.3.4.2.1";

    private static final string default_prng_name = "sha1prng";

    private digest messdigest;

    private securerandom sr;

    /**
     * the mceliece main parameters
     */
    private int n, k, t;

    mceliececca2keyparameters key;


    public void init(boolean forsigning,
                     cipherparameters param)
    {

        if (forsigning)
        {
            if (param instanceof parameterswithrandom)
            {
                parameterswithrandom rparam = (parameterswithrandom)param;

                this.sr = rparam.getrandom();
                this.key = (mceliececca2publickeyparameters)rparam.getparameters();
                this.initcipherencrypt((mceliececca2publickeyparameters)key);

            }
            else
            {
                this.sr = new securerandom();
                this.key = (mceliececca2publickeyparameters)param;
                this.initcipherencrypt((mceliececca2publickeyparameters)key);
            }
        }
        else
        {
            this.key = (mceliececca2privatekeyparameters)param;
            this.initcipherdecrypt((mceliececca2privatekeyparameters)key);
        }

    }


    public int getkeysize(mceliececca2keyparameters key)
        throws illegalargumentexception
    {

        if (key instanceof mceliececca2publickeyparameters)
        {
            return ((mceliececca2publickeyparameters)key).getn();

        }
        if (key instanceof mceliececca2privatekeyparameters)
        {
            return ((mceliececca2privatekeyparameters)key).getn();
        }
        throw new illegalargumentexception("unsupported type");

    }


    private void initcipherencrypt(mceliececca2publickeyparameters pubkey)
    {
        this.sr = sr != null ? sr : new securerandom();
        this.messdigest = pubkey.getparameters().getdigest();
        n = pubkey.getn();
        k = pubkey.getk();
        t = pubkey.gett();
    }


    public void initcipherdecrypt(mceliececca2privatekeyparameters privkey)
    {
        this.messdigest = privkey.getparameters().getdigest();
        n = privkey.getn();
        t = privkey.gett();
    }


    public byte[] messageencrypt(byte[] input)
        throws exception
    {

        // generate random vector r of length k bits
        gf2vector r = new gf2vector(k, sr);

        // convert r to byte array
        byte[] rbytes = r.getencoded();

        // compute (r||input)
        byte[] rm = byteutils.concatenate(rbytes, input);

        // compute h(r||input)
        messdigest.update(rm, 0, rm.length);
        byte[] hrm = new byte[messdigest.getdigestsize()];
        messdigest.dofinal(hrm, 0);

        // convert h(r||input) to error vector z
        gf2vector z = conversions.encode(n, t, hrm);

        // compute c1 = e(r, z)
        byte[] c1 = mceliececca2primitives.encryptionprimitive((mceliececca2publickeyparameters)key, r, z)
            .getencoded();

        // get prng object
        digestrandomgenerator sr0 = new digestrandomgenerator(new sha1digest());

        // seed prng with r'
        sr0.addseedmaterial(rbytes);

        // generate random c2
        byte[] c2 = new byte[input.length];
        sr0.nextbytes(c2);

        // xor with input
        for (int i = 0; i < input.length; i++)
        {
            c2[i] ^= input[i];
        }

        // return (c1||c2)
        return byteutils.concatenate(c1, c2);
    }

    public byte[] messagedecrypt(byte[] input)
        throws exception
    {

        int c1len = (n + 7) >> 3;
        int c2len = input.length - c1len;

        // split ciphertext (c1||c2)
        byte[][] c1c2 = byteutils.split(input, c1len);
        byte[] c1 = c1c2[0];
        byte[] c2 = c1c2[1];

        // decrypt c1 ...
        gf2vector hrmvec = gf2vector.os2vp(n, c1);
        gf2vector[] decc1 = mceliececca2primitives.decryptionprimitive((mceliececca2privatekeyparameters)key,
            hrmvec);
        byte[] rbytes = decc1[0].getencoded();
        // ... and obtain error vector z
        gf2vector z = decc1[1];

        // get prng object
        digestrandomgenerator sr0 = new digestrandomgenerator(new sha1digest());

        // seed prng with r'
        sr0.addseedmaterial(rbytes);

        // generate random sequence
        byte[] mbytes = new byte[c2len];
        sr0.nextbytes(mbytes);

        // xor with c2 to obtain m
        for (int i = 0; i < c2len; i++)
        {
            mbytes[i] ^= c2[i];
        }

        // compute h(r||m)
        byte[] rmbytes = byteutils.concatenate(rbytes, mbytes);
        byte[] hrm = new byte[messdigest.getdigestsize()];
        messdigest.update(rmbytes, 0, rmbytes.length);
        messdigest.dofinal(hrm, 0);


        // compute conv(h(r||m))
        hrmvec = conversions.encode(n, t, hrm);

        // check that conv(h(m||r)) = z
        if (!hrmvec.equals(z))
        {

            throw new exception("bad padding: invalid ciphertext");

        }

        // return plaintext m
        return mbytes;
    }


}
