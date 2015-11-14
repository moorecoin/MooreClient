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
import org.ripple.bouncycastle.pqc.math.linearalgebra.integerfunctions;

/**
 * this class implements the kobara/imai conversion of the mceliecepkcs. this is
 * a conversion of the mceliecepkcs which is cca2-secure. for details, see d.
 * engelbert, r. overbeck, a. schmidt, "a summary of the development of the
 * mceliece cryptosystem", technical report.
 */
public class mceliecekobaraimaicipher
    implements messageencryptor
{

    /**
     * the oid of the algorithm.
     */
    public static final string oid = "1.3.6.1.4.1.8301.3.1.3.4.2.3";

    private static final string default_prng_name = "sha1prng";

    /**
     * a predetermined public constant.
     */
    public static final byte[] public_constant = "a predetermined public constant"
        .getbytes();


    private digest messdigest;

    private securerandom sr;

    mceliececca2keyparameters key;

    /**
     * the mceliece main parameters
     */
    private int n, k, t;


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
     */
    public int getkeysize(mceliececca2keyparameters key)
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

        int c2len = messdigest.getdigestsize();
        int c4len = k >> 3;
        int c5len = (integerfunctions.binomial(n, t).bitlength() - 1) >> 3;


        int mlen = c4len + c5len - c2len - public_constant.length;
        if (input.length > mlen)
        {
            mlen = input.length;
        }

        int c1len = mlen + public_constant.length;
        int c6len = c1len + c2len - c4len - c5len;

        // compute (m||const)
        byte[] mconst = new byte[c1len];
        system.arraycopy(input, 0, mconst, 0, input.length);
        system.arraycopy(public_constant, 0, mconst, mlen,
            public_constant.length);

        // generate random r of length c2len bytes
        byte[] r = new byte[c2len];
        sr.nextbytes(r);

        // get prng object
                // get prng object
        digestrandomgenerator sr0 = new digestrandomgenerator(new sha1digest());

        // seed prng with r'
        sr0.addseedmaterial(r);

        // generate random sequence ...
        byte[] c1 = new byte[c1len];
        sr0.nextbytes(c1);

        // ... and xor with (m||const) to obtain c1
        for (int i = c1len - 1; i >= 0; i--)
        {
            c1[i] ^= mconst[i];
        }

        // compute h(c1) ...
        byte[] c2 = new byte[messdigest.getdigestsize()];
        messdigest.update(c1, 0, c1.length);
        messdigest.dofinal(c2, 0);

        // ... and xor with r
        for (int i = c2len - 1; i >= 0; i--)
        {
            c2[i] ^= r[i];
        }

        // compute (c2||c1)
        byte[] c2c1 = byteutils.concatenate(c2, c1);

        // split (c2||c1) into (c6||c5||c4), where c4len is k/8 bytes, c5len is
        // floor[log(n|t)]/8 bytes, and c6len is c1len+c2len-c4len-c5len (may be
        // 0).
        byte[] c6 = new byte[0];
        if (c6len > 0)
        {
            c6 = new byte[c6len];
            system.arraycopy(c2c1, 0, c6, 0, c6len);
        }

        byte[] c5 = new byte[c5len];
        system.arraycopy(c2c1, c6len, c5, 0, c5len);

        byte[] c4 = new byte[c4len];
        system.arraycopy(c2c1, c6len + c5len, c4, 0, c4len);

        // convert c4 to vector over gf(2)
        gf2vector c4vec = gf2vector.os2vp(k, c4);

        // convert c5 to error vector z
        gf2vector z = conversions.encode(n, t, c5);

        // compute encc4 = e(c4, z)
        byte[] encc4 = mceliececca2primitives.encryptionprimitive((mceliececca2publickeyparameters)key,
            c4vec, z).getencoded();

        // if c6len > 0
        if (c6len > 0)
        {
            // return (c6||encc4)
            return byteutils.concatenate(c6, encc4);
        }
        // else, return encc4
        return encc4;
    }


    public byte[] messagedecrypt(byte[] input)
        throws exception
    {

        int ndiv8 = n >> 3;

        if (input.length < ndiv8)
        {
            throw new exception("bad padding: ciphertext too short.");
        }

        int c2len = messdigest.getdigestsize();
        int c4len = k >> 3;
        int c6len = input.length - ndiv8;

        // split cipher text (c6||encc4), where c6 may be empty
        byte[] c6, encc4;
        if (c6len > 0)
        {
            byte[][] c6encc4 = byteutils.split(input, c6len);
            c6 = c6encc4[0];
            encc4 = c6encc4[1];
        }
        else
        {
            c6 = new byte[0];
            encc4 = input;
        }

        // convert encc4 into vector over gf(2)
        gf2vector encc4vec = gf2vector.os2vp(n, encc4);

        // decrypt encc4vec to obtain c4 and error vector z
        gf2vector[] c4z = mceliececca2primitives.decryptionprimitive((mceliececca2privatekeyparameters)key,
            encc4vec);
        byte[] c4 = c4z[0].getencoded();
        gf2vector z = c4z[1];

        // if length of c4 is greater than c4len (because of padding) ...
        if (c4.length > c4len)
        {
            // ... truncate the padding bytes
            c4 = byteutils.subarray(c4, 0, c4len);
        }

        // compute c5 = conv^-1(z)
        byte[] c5 = conversions.decode(n, t, z);

        // compute (c6||c5||c4)
        byte[] c6c5c4 = byteutils.concatenate(c6, c5);
        c6c5c4 = byteutils.concatenate(c6c5c4, c4);

        // split (c6||c5||c4) into (c2||c1), where c2len = mdlen and c1len =
        // input.length-c2len bytes.
        int c1len = c6c5c4.length - c2len;
        byte[][] c2c1 = byteutils.split(c6c5c4, c2len);
        byte[] c2 = c2c1[0];
        byte[] c1 = c2c1[1];

        // compute h(c1) ...
        byte[] rprime = new byte[messdigest.getdigestsize()];
        messdigest.update(c1, 0, c1.length);
        messdigest.dofinal(rprime, 0);

        // ... and xor with c2 to obtain r'
        for (int i = c2len - 1; i >= 0; i--)
        {
            rprime[i] ^= c2[i];
        }

        // get prng object
        digestrandomgenerator sr0 = new digestrandomgenerator(new sha1digest());

        // seed prng with r'
        sr0.addseedmaterial(rprime);

        // generate random sequence r(r') ...
        byte[] mconstprime = new byte[c1len];
        sr0.nextbytes(mconstprime);

        // ... and xor with c1 to obtain (m||const')
        for (int i = c1len - 1; i >= 0; i--)
        {
            mconstprime[i] ^= c1[i];
        }

        if (mconstprime.length < c1len)
        {
            throw new exception("bad padding: invalid ciphertext");
        }

        byte[][] temp = byteutils.split(mconstprime, c1len
            - public_constant.length);
        byte[] mr = temp[0];
        byte[] constprime = temp[1];

        if (!byteutils.equals(constprime, public_constant))
        {
            throw new exception("bad padding: invalid ciphertext");
        }

        return mr;
    }


}
