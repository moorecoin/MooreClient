package org.ripple.bouncycastle.pqc.crypto.ntru;

import java.security.securerandom;

import org.ripple.bouncycastle.crypto.asymmetricblockcipher;
import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.datalengthexception;
import org.ripple.bouncycastle.crypto.digest;
import org.ripple.bouncycastle.crypto.invalidciphertextexception;
import org.ripple.bouncycastle.crypto.params.parameterswithrandom;
import org.ripple.bouncycastle.pqc.math.ntru.polynomial.denseternarypolynomial;
import org.ripple.bouncycastle.pqc.math.ntru.polynomial.integerpolynomial;
import org.ripple.bouncycastle.pqc.math.ntru.polynomial.polynomial;
import org.ripple.bouncycastle.pqc.math.ntru.polynomial.productformpolynomial;
import org.ripple.bouncycastle.pqc.math.ntru.polynomial.sparseternarypolynomial;
import org.ripple.bouncycastle.pqc.math.ntru.polynomial.ternarypolynomial;
import org.ripple.bouncycastle.util.arrays;

/**
 * encrypts, decrypts data and generates key pairs.<br/>
 * the parameter p is hardcoded to 3.
 */
public class ntruengine
    implements asymmetricblockcipher
{
    private boolean forencryption;
    private ntruencryptionparameters params;
    private ntruencryptionpublickeyparameters pubkey;
    private ntruencryptionprivatekeyparameters privkey;
    private securerandom random;

    /**
     * constructs a new instance with a set of encryption parameters.
     *
     */
    public ntruengine()
    {
    }

    public void init(boolean forencryption, cipherparameters parameters)
    {
        this.forencryption = forencryption;
        if (forencryption)
        {
            if (parameters instanceof parameterswithrandom)
            {
                parameterswithrandom p = (parameterswithrandom)parameters;

                this.random = p.getrandom();
                this.pubkey = (ntruencryptionpublickeyparameters)p.getparameters();
            }
            else
            {
                this.random = new securerandom();
                this.pubkey = (ntruencryptionpublickeyparameters)parameters;
            }

            this.params = pubkey.getparameters();
        }
        else
        {
            this.privkey = (ntruencryptionprivatekeyparameters)parameters;
            this.params = privkey.getparameters();
        }
    }

    public int getinputblocksize()
    {
        return params.maxmsglenbytes;
    }

    public int getoutputblocksize()
    {
        return ((params.n * log2(params.q)) + 7) / 8;
    }

    public byte[] processblock(byte[] in, int inoff, int len)
        throws invalidciphertextexception
    {
        byte[] tmp = new byte[len];

        system.arraycopy(in, inoff, tmp, 0, len);

        if (forencryption)
        {
            return encrypt(tmp, pubkey);
        }
        else
        {
            return decrypt(tmp, privkey);
        }
    }

    /**
     * encrypts a message.<br/>
     * see p1363.1 section 9.2.2.
     *
     * @param m      the message to encrypt
     * @param pubkey the public key to encrypt the message with
     * @return the encrypted message
     */
    private byte[] encrypt(byte[] m, ntruencryptionpublickeyparameters pubkey)
    {
        integerpolynomial pub = pubkey.h;
        int n = params.n;
        int q = params.q;

        int maxlenbytes = params.maxmsglenbytes;
        int db = params.db;
        int bufferlenbits = params.bufferlenbits;
        int dm0 = params.dm0;
        int pklen = params.pklen;
        int mincallsmask = params.mincallsmask;
        boolean hashseed = params.hashseed;
        byte[] oid = params.oid;

        int l = m.length;
        if (maxlenbytes > 255)
        {
            throw new illegalargumentexception("llen values bigger than 1 are not supported");
        }
        if (l > maxlenbytes)
        {
            throw new datalengthexception("message too long: " + l + ">" + maxlenbytes);
        }

        while (true)
        {
            // m = b|octl|m|p0
            byte[] b = new byte[db / 8];
            random.nextbytes(b);
            byte[] p0 = new byte[maxlenbytes + 1 - l];
            byte[] m = new byte[bufferlenbits / 8];

            system.arraycopy(b, 0, m, 0, b.length);
            m[b.length] = (byte)l;
            system.arraycopy(m, 0, m, b.length + 1, m.length);
            system.arraycopy(p0, 0, m, b.length + 1 + m.length, p0.length);

            integerpolynomial mtrin = integerpolynomial.frombinary3sves(m, n);

            // sdata = oid|m|b|htrunc
            byte[] bh = pub.tobinary(q);
            byte[] htrunc = copyof(bh, pklen / 8);
            byte[] sdata = buildsdata(oid, m, l, b, htrunc);

            polynomial r = generateblindingpoly(sdata, m);
            integerpolynomial r = r.mult(pub, q);
            integerpolynomial r4 = (integerpolynomial)r.clone();
            r4.modpositive(4);
            byte[] or4 = r4.tobinary(4);
            integerpolynomial mask = mgf(or4, n, mincallsmask, hashseed);
            mtrin.add(mask);
            mtrin.mod3();

            if (mtrin.count(-1) < dm0)
            {
                continue;
            }
            if (mtrin.count(0) < dm0)
            {
                continue;
            }
            if (mtrin.count(1) < dm0)
            {
                continue;
            }

            r.add(mtrin, q);
            r.ensurepositive(q);
            return r.tobinary(q);
        }
    }

    private byte[] buildsdata(byte[] oid, byte[] m, int l, byte[] b, byte[] htrunc)
    {
        byte[] sdata = new byte[oid.length + l + b.length + htrunc.length];

        system.arraycopy(oid, 0, sdata, 0, oid.length);
        system.arraycopy(m, 0, sdata, oid.length, m.length);
        system.arraycopy(b, 0, sdata, oid.length + m.length, b.length);
        system.arraycopy(htrunc, 0, sdata, oid.length + m.length + b.length, htrunc.length);
        return sdata;
    }

    protected integerpolynomial encrypt(integerpolynomial m, ternarypolynomial r, integerpolynomial pubkey)
    {
        integerpolynomial e = r.mult(pubkey, params.q);
        e.add(m, params.q);
        e.ensurepositive(params.q);
        return e;
    }

    /**
     * deterministically generates a blinding polynomial from a seed and a message representative.
     *
     * @param seed
     * @param m    message representative
     * @return a blinding polynomial
     */
    private polynomial generateblindingpoly(byte[] seed, byte[] m)
    {
        indexgenerator ig = new indexgenerator(seed, params);

        if (params.polytype == ntruparameters.ternary_polynomial_type_product)
        {
            sparseternarypolynomial r1 = new sparseternarypolynomial(generateblindingcoeffs(ig, params.dr1));
            sparseternarypolynomial r2 = new sparseternarypolynomial(generateblindingcoeffs(ig, params.dr2));
            sparseternarypolynomial r3 = new sparseternarypolynomial(generateblindingcoeffs(ig, params.dr3));
            return new productformpolynomial(r1, r2, r3);
        }
        else
        {
            int dr = params.dr;
            boolean sparse = params.sparse;
            int[] r = generateblindingcoeffs(ig, dr);
            if (sparse)
            {
                return new sparseternarypolynomial(r);
            }
            else
            {
                return new denseternarypolynomial(r);
            }
        }
    }

    /**
     * generates an <code>int</code> array containing <code>dr</code> elements equal to <code>1</code>
     * and <code>dr</code> elements equal to <code>-1</code> using an index generator.
     *
     * @param ig an index generator
     * @param dr number of ones / negative ones
     * @return an array containing numbers between <code>-1</code> and <code>1</code>
     */
    private int[] generateblindingcoeffs(indexgenerator ig, int dr)
    {
        int n = params.n;

        int[] r = new int[n];
        for (int coeff = -1; coeff <= 1; coeff += 2)
        {
            int t = 0;
            while (t < dr)
            {
                int i = ig.nextindex();
                if (r[i] == 0)
                {
                    r[i] = coeff;
                    t++;
                }
            }
        }

        return r;
    }

    /**
     * an implementation of mgf-tp-1 from p1363.1 section 8.4.1.1.
     *
     * @param seed
     * @param n
     * @param mincallsr
     * @param hashseed  whether to hash the seed
     * @return
     */
    private integerpolynomial mgf(byte[] seed, int n, int mincallsr, boolean hashseed)
    {
        digest hashalg = params.hashalg;
        int hashlen = hashalg.getdigestsize();
        byte[] buf = new byte[mincallsr * hashlen];
        byte[] z = hashseed ? calchash(hashalg, seed) : seed;
        int counter = 0;
        while (counter < mincallsr)
        {
            hashalg.update(z, 0, z.length);
            putint(hashalg, counter);

            byte[] hash = calchash(hashalg);
            system.arraycopy(hash, 0, buf, counter * hashlen, hashlen);
            counter++;
        }

        integerpolynomial i = new integerpolynomial(n);
        while (true)
        {
            int cur = 0;
            for (int index = 0; index != buf.length; index++)
            {
                int o = (int)buf[index] & 0xff;
                if (o >= 243)   // 243 = 3^5
                {
                    continue;
                }

                for (int teridx = 0; teridx < 4; teridx++)
                {
                    int rem3 = o % 3;
                    i.coeffs[cur] = rem3 - 1;
                    cur++;
                    if (cur == n)
                    {
                        return i;
                    }
                    o = (o - rem3) / 3;
                }

                i.coeffs[cur] = o - 1;
                cur++;
                if (cur == n)
                {
                    return i;
                }
            }

            if (cur >= n)
            {
                return i;
            }

            hashalg.update(z, 0, z.length);
            putint(hashalg, counter);

            byte[] hash = calchash(hashalg);

            buf = hash;

            counter++;
        }
    }

    private void putint(digest hashalg, int counter)
    {
        hashalg.update((byte)(counter >> 24));
        hashalg.update((byte)(counter >> 16));
        hashalg.update((byte)(counter >> 8));
        hashalg.update((byte)counter);
    }

    private byte[] calchash(digest hashalg)
    {
        byte[] tmp = new byte[hashalg.getdigestsize()];

        hashalg.dofinal(tmp, 0);

        return tmp;
    }

    private byte[] calchash(digest hashalg, byte[] input)
    {
        byte[] tmp = new byte[hashalg.getdigestsize()];

        hashalg.update(input, 0, input.length);
        hashalg.dofinal(tmp, 0);

        return tmp;
    }
    /**
     * decrypts a message.<br/>
     * see p1363.1 section 9.2.3.
     *
     * @param data the message to decrypt
     * @param privkey   the corresponding private key
     * @return the decrypted message
     * @throws invalidciphertextexception if  the encrypted data is invalid, or <code>maxlenbytes</code> is greater than 255
     */
    private byte[] decrypt(byte[] data, ntruencryptionprivatekeyparameters privkey)
        throws invalidciphertextexception
    {
        polynomial priv_t = privkey.t;
        integerpolynomial priv_fp = privkey.fp;
        integerpolynomial pub = privkey.h;
        int n = params.n;
        int q = params.q;
        int db = params.db;
        int maxmsglenbytes = params.maxmsglenbytes;
        int dm0 = params.dm0;
        int pklen = params.pklen;
        int mincallsmask = params.mincallsmask;
        boolean hashseed = params.hashseed;
        byte[] oid = params.oid;

        if (maxmsglenbytes > 255)
        {
            throw new datalengthexception("maxmsglenbytes values bigger than 255 are not supported");
        }

        int blen = db / 8;

        integerpolynomial e = integerpolynomial.frombinary(data, n, q);
        integerpolynomial ci = decrypt(e, priv_t, priv_fp);

        if (ci.count(-1) < dm0)
        {
            throw new invalidciphertextexception("less than dm0 coefficients equal -1");
        }
        if (ci.count(0) < dm0)
        {
            throw new invalidciphertextexception("less than dm0 coefficients equal 0");
        }
        if (ci.count(1) < dm0)
        {
            throw new invalidciphertextexception("less than dm0 coefficients equal 1");
        }

        integerpolynomial cr = (integerpolynomial)e.clone();
        cr.sub(ci);
        cr.modpositive(q);
        integerpolynomial cr4 = (integerpolynomial)cr.clone();
        cr4.modpositive(4);
        byte[] cor4 = cr4.tobinary(4);
        integerpolynomial mask = mgf(cor4, n, mincallsmask, hashseed);
        integerpolynomial cmtrin = ci;
        cmtrin.sub(mask);
        cmtrin.mod3();
        byte[] cm = cmtrin.tobinary3sves();

        byte[] cb = new byte[blen];
        system.arraycopy(cm, 0, cb, 0, blen);
        int cl = cm[blen] & 0xff;   // llen=1, so read one byte
        if (cl > maxmsglenbytes)
        {
            throw new invalidciphertextexception("message too long: " + cl + ">" + maxmsglenbytes);
        }
        byte[] cm = new byte[cl];
        system.arraycopy(cm, blen + 1, cm, 0, cl);
        byte[] p0 = new byte[cm.length - (blen + 1 + cl)];
        system.arraycopy(cm, blen + 1 + cl, p0, 0, p0.length);
        if (!arrays.areequal(p0, new byte[p0.length]))
        {
           throw new invalidciphertextexception("the message is not followed by zeroes");
        }

        // sdata = oid|m|b|htrunc
        byte[] bh = pub.tobinary(q);
        byte[] htrunc = copyof(bh, pklen / 8);
        byte[] sdata = buildsdata(oid, cm, cl, cb, htrunc);

        polynomial cr = generateblindingpoly(sdata, cm);
        integerpolynomial crprime = cr.mult(pub);
        crprime.modpositive(q);
        if (!crprime.equals(cr))
        {
            throw new invalidciphertextexception("invalid message encoding");
        }

        return cm;
    }

    /**
     * @param e
     * @param priv_t  a polynomial such that if <code>fastfp=true</code>, <code>f=1+3*priv_t</code>; otherwise, <code>f=priv_t</code>
     * @param priv_fp
     * @return
     */
    protected integerpolynomial decrypt(integerpolynomial e, polynomial priv_t, integerpolynomial priv_fp)
    {
        integerpolynomial a;
        if (params.fastfp)
        {
            a = priv_t.mult(e, params.q);
            a.mult(3);
            a.add(e);
        }
        else
        {
            a = priv_t.mult(e, params.q);
        }
        a.center0(params.q);
        a.mod3();

        integerpolynomial c = params.fastfp ? a : new denseternarypolynomial(a).mult(priv_fp, 3);
        c.center0(3);
        return c;
    }

    private byte[] copyof(byte[] src, int len)
    {
        byte[] tmp = new byte[len];

        system.arraycopy(src, 0, tmp, 0, len < src.length ? len : src.length);

        return tmp;
    }

    private int log2(int value)
    {
        if (value == 2048)
        {
            return 11;
        }

        throw new illegalstateexception("log2 not fully implemented");
    }
}