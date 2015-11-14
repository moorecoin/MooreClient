package org.ripple.bouncycastle.pqc.crypto.mceliece;

import java.security.securerandom;

import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.params.parameterswithrandom;
import org.ripple.bouncycastle.pqc.crypto.messageencryptor;
import org.ripple.bouncycastle.pqc.math.linearalgebra.gf2matrix;
import org.ripple.bouncycastle.pqc.math.linearalgebra.gf2vector;
import org.ripple.bouncycastle.pqc.math.linearalgebra.gf2mfield;
import org.ripple.bouncycastle.pqc.math.linearalgebra.goppacode;
import org.ripple.bouncycastle.pqc.math.linearalgebra.permutation;
import org.ripple.bouncycastle.pqc.math.linearalgebra.polynomialgf2msmallm;
import org.ripple.bouncycastle.pqc.math.linearalgebra.vector;

/**
 * this class implements the mceliece public key cryptosystem (mceliecepkcs). it
 * was first described in r.j. mceliece, "a public key cryptosystem based on
 * algebraic coding theory", dsn progress report, 42-44:114-116, 1978. the
 * mceliecepkcs is the first cryptosystem which is based on error correcting
 * codes. the trapdoor for the mceliece cryptosystem using goppa codes is the
 * knowledge of the goppa polynomial used to generate the code.
 */
public class mceliecepkcscipher
    implements messageencryptor
{

    /**
     * the oid of the algorithm.
     */
    public static final string oid = "1.3.6.1.4.1.8301.3.1.3.4.1";


    // the source of randomness
    private securerandom sr;

    // the mceliece main parameters
    private int n, k, t;

    // the maximum number of bytes the cipher can decrypt
    public int maxplaintextsize;

    // the maximum number of bytes the cipher can encrypt
    public int ciphertextsize;

    mceliecekeyparameters key;


    public void init(boolean forsigning,
                     cipherparameters param)
    {

        if (forsigning)
        {
            if (param instanceof parameterswithrandom)
            {
                parameterswithrandom rparam = (parameterswithrandom)param;

                this.sr = rparam.getrandom();
                this.key = (mceliecepublickeyparameters)rparam.getparameters();
                this.initcipherencrypt((mceliecepublickeyparameters)key);

            }
            else
            {
                this.sr = new securerandom();
                this.key = (mceliecepublickeyparameters)param;
                this.initcipherencrypt((mceliecepublickeyparameters)key);
            }
        }
        else
        {
            this.key = (mcelieceprivatekeyparameters)param;
            this.initcipherdecrypt((mcelieceprivatekeyparameters)key);
        }

    }


    /**
     * return the key size of the given key object.
     *
     * @param key the mceliecekeyparameters object
     * @return the keysize of the given key object
     */

    public int getkeysize(mceliecekeyparameters key)
    {

        if (key instanceof mceliecepublickeyparameters)
        {
            return ((mceliecepublickeyparameters)key).getn();

        }
        if (key instanceof mcelieceprivatekeyparameters)
        {
            return ((mcelieceprivatekeyparameters)key).getn();
        }
        throw new illegalargumentexception("unsupported type");

    }


    public void initcipherencrypt(mceliecepublickeyparameters pubkey)
    {
        this.sr = sr != null ? sr : new securerandom();
        n = pubkey.getn();
        k = pubkey.getk();
        t = pubkey.gett();
        ciphertextsize = n >> 3;
        maxplaintextsize = (k >> 3);
    }


    public void initcipherdecrypt(mcelieceprivatekeyparameters privkey)
    {
        n = privkey.getn();
        k = privkey.getk();

        maxplaintextsize = (k >> 3);
        ciphertextsize = n >> 3;
    }

    /**
     * encrypt a plain text.
     *
     * @param input the plain text
     * @return the cipher text
     */
    public byte[] messageencrypt(byte[] input)
    {
        gf2vector m = computemessagerepresentative(input);
        gf2vector z = new gf2vector(n, t, sr);

        gf2matrix g = ((mceliecepublickeyparameters)key).getg();
        vector mg = g.leftmultiply(m);
        gf2vector mgz = (gf2vector)mg.add(z);

        return mgz.getencoded();
    }

    private gf2vector computemessagerepresentative(byte[] input)
    {
        byte[] data = new byte[maxplaintextsize + ((k & 0x07) != 0 ? 1 : 0)];
        system.arraycopy(input, 0, data, 0, input.length);
        data[input.length] = 0x01;
        return gf2vector.os2vp(k, data);
    }

    /**
     * decrypt a cipher text.
     *
     * @param input the cipher text
     * @return the plain text
     * @throws exception if the cipher text is invalid.
     */
    public byte[] messagedecrypt(byte[] input)
        throws exception
    {
        gf2vector vec = gf2vector.os2vp(n, input);
        mcelieceprivatekeyparameters privkey = (mcelieceprivatekeyparameters)key;
        gf2mfield field = privkey.getfield();
        polynomialgf2msmallm gp = privkey.getgoppapoly();
        gf2matrix sinv = privkey.getsinv();
        permutation p1 = privkey.getp1();
        permutation p2 = privkey.getp2();
        gf2matrix h = privkey.geth();
        polynomialgf2msmallm[] qinv = privkey.getqinv();

        // compute permutation p = p1 * p2
        permutation p = p1.rightmultiply(p2);

        // compute p^-1
        permutation pinv = p.computeinverse();

        // compute c p^-1
        gf2vector cpinv = (gf2vector)vec.multiply(pinv);

        // compute syndrome of c p^-1
        gf2vector syndrome = (gf2vector)h.rightmultiply(cpinv);

        // decode syndrome
        gf2vector z = goppacode.syndromedecode(syndrome, field, gp, qinv);
        gf2vector msg = (gf2vector)cpinv.add(z);

        // multiply codeword with p1 and error vector with p
        msg = (gf2vector)msg.multiply(p1);
        z = (gf2vector)z.multiply(p);

        // extract ms (last k columns of msg)
        gf2vector ms = msg.extractrightvector(k);

        // compute plaintext vector
        gf2vector mvec = (gf2vector)sinv.leftmultiply(ms);

        // compute and return plaintext
        return computemessage(mvec);
    }

    private byte[] computemessage(gf2vector mr)
        throws exception
    {
        byte[] mrbytes = mr.getencoded();
        // find first non-zero byte
        int index;
        for (index = mrbytes.length - 1; index >= 0 && mrbytes[index] == 0; index--)
        {
            ;
        }

        // check if padding byte is valid
        if (mrbytes[index] != 0x01)
        {
            throw new exception("bad padding: invalid ciphertext");
        }

        // extract and return message
        byte[] mbytes = new byte[index];
        system.arraycopy(mrbytes, 0, mbytes, 0, index);
        return mbytes;
    }


}
