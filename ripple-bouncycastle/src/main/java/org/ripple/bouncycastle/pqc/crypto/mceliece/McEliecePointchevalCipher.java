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
 * this class implements the pointcheval conversion of the mceliecepkcs.
 * pointcheval presents a generic technique to make a cca2-secure cryptosystem
 * from any partially trapdoor one-way function in the random oracle model. for
 * details, see d. engelbert, r. overbeck, a. schmidt, "a summary of the
 * development of the mceliece cryptosystem", technical report.
 */
public class mceliecepointchevalcipher
    implements messageencryptor
{


    /**
     * the oid of the algorithm.
     */
    public static final string oid = "1.3.6.1.4.1.8301.3.1.3.4.2.2";

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

    /**
     * return the key size of the given key object.
     *
     * @param key the mceliececca2keyparameters object
     * @return the key size of the given key object
     * @throws illegalargumentexception if the key is invalid
     */
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


    protected int decryptoutputsize(int inlen)
    {
        return 0;
    }

    protected int encryptoutputsize(int inlen)
    {
        return 0;
    }


    public void initcipherencrypt(mceliececca2publickeyparameters pubkey)
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
        k = privkey.getk();
        t = privkey.gett();
    }

    public byte[] messageencrypt(byte[] input)
        throws exception
    {

        int kdiv8 = k >> 3;

        // generate random r of length k div 8 bytes
        byte[] r = new byte[kdiv8];
        sr.nextbytes(r);

        // generate random vector r' of length k bits
        gf2vector rprime = new gf2vector(k, sr);

        // convert r' to byte array
        byte[] rprimebytes = rprime.getencoded();

        // compute (input||r)
        byte[] mr = byteutils.concatenate(input, r);

        // compute h(input||r)
        messdigest.update(mr, 0, mr.length);
        byte[] hmr = new byte[messdigest.getdigestsize()];
        messdigest.dofinal(hmr, 0);


        // convert h(input||r) to error vector z
        gf2vector z = conversions.encode(n, t, hmr);

        // compute c1 = e(rprime, z)
        byte[] c1 = mceliececca2primitives.encryptionprimitive((mceliececca2publickeyparameters)key, rprime,
            z).getencoded();

        // get prng object
        digestrandomgenerator sr0 = new digestrandomgenerator(new sha1digest());

        // seed prng with r'
        sr0.addseedmaterial(rprimebytes);

        // generate random c2
        byte[] c2 = new byte[input.length + kdiv8];
        sr0.nextbytes(c2);

        // xor with input
        for (int i = 0; i < input.length; i++)
        {
            c2[i] ^= input[i];
        }
        // xor with r
        for (int i = 0; i < kdiv8; i++)
        {
            c2[input.length + i] ^= r[i];
        }

        // return (c1||c2)
        return byteutils.concatenate(c1, c2);
    }

    public byte[] messagedecrypt(byte[] input)
        throws exception
    {

        int c1len = (n + 7) >> 3;
        int c2len = input.length - c1len;

        // split cipher text (c1||c2)
        byte[][] c1c2 = byteutils.split(input, c1len);
        byte[] c1 = c1c2[0];
        byte[] c2 = c1c2[1];

        // decrypt c1 ...
        gf2vector c1vec = gf2vector.os2vp(n, c1);
        gf2vector[] c1dec = mceliececca2primitives.decryptionprimitive((mceliececca2privatekeyparameters)key,
            c1vec);
        byte[] rprimebytes = c1dec[0].getencoded();
        // ... and obtain error vector z
        gf2vector z = c1dec[1];

        // get prng object
        digestrandomgenerator sr0 = new digestrandomgenerator(new sha1digest());

        // seed prng with r'
        sr0.addseedmaterial(rprimebytes);

        // generate random sequence
        byte[] mrbytes = new byte[c2len];
        sr0.nextbytes(mrbytes);

        // xor with c2 to obtain (m||r)
        for (int i = 0; i < c2len; i++)
        {
            mrbytes[i] ^= c2[i];
        }

        // compute h(m||r)
        messdigest.update(mrbytes, 0, mrbytes.length);
        byte[] hmr = new byte[messdigest.getdigestsize()];
        messdigest.dofinal(hmr, 0);

        // compute conv(h(m||r))
        c1vec = conversions.encode(n, t, hmr);

        // check that conv(h(m||r)) = z
        if (!c1vec.equals(z))
        {
            throw new exception("bad padding: invalid ciphertext.");
        }

        // split (m||r) to obtain m
        int kdiv8 = k >> 3;
        byte[][] mr = byteutils.split(mrbytes, c2len - kdiv8);

        // return plain text m
        return mr[0];
    }


}
