package org.ripple.bouncycastle.pqc.crypto.ntru;

import java.nio.bytebuffer;

import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.digest;
import org.ripple.bouncycastle.pqc.math.ntru.polynomial.integerpolynomial;
import org.ripple.bouncycastle.pqc.math.ntru.polynomial.polynomial;

/**
 * signs, verifies data and generates key pairs.
 */
public class ntrusigner
{
    private ntrusigningparameters params;
    private digest hashalg;
    private ntrusigningprivatekeyparameters signingkeypair;
    private ntrusigningpublickeyparameters verificationkey;

    /**
     * constructs a new instance with a set of signature parameters.
     *
     * @param params signature parameters
     */
    public ntrusigner(ntrusigningparameters params)
    {
        this.params = params;
    }

    /**
     * resets the engine for signing a message.
     *
     * @param forsigning
     * @param params
     */
    public void init(boolean forsigning, cipherparameters params)
    {
        if (forsigning)
        {
            this.signingkeypair = (ntrusigningprivatekeyparameters)params;
        }
        else
        {
            this.verificationkey = (ntrusigningpublickeyparameters)params;
        }
        hashalg = this.params.hashalg;
        hashalg.reset();
    }

    /**
      * adds data to sign or verify.
      *
      * @param b data
      */
     public void update(byte b)
     {
         if (hashalg == null)
         {
             throw new illegalstateexception("call initsign or initverify first!");
         }

         hashalg.update(b);
     }

    /**
     * adds data to sign or verify.
     *
     * @param m data
     * @param off offset
     * @param length number of bytes
     */
    public void update(byte[] m, int off, int length)
    {
        if (hashalg == null)
        {
            throw new illegalstateexception("call initsign or initverify first!");
        }

        hashalg.update(m, off, length);
    }

    /**
     * adds data to sign and computes a signature over this data and any data previously added via {@link #update(byte[], int, int)}.
     *
     * @return a signature
     * @throws illegalstateexception if <code>initsign</code> was not called
     */
    public byte[] generatesignature()
    {
        if (hashalg == null || signingkeypair == null)
        {
            throw new illegalstateexception("call initsign first!");
        }

        byte[] msghash = new byte[hashalg.getdigestsize()];

        hashalg.dofinal(msghash, 0);
        return signhash(msghash, signingkeypair);
    }

    private byte[] signhash(byte[] msghash, ntrusigningprivatekeyparameters kp)
    {
        int r = 0;
        integerpolynomial s;
        integerpolynomial i;

        ntrusigningpublickeyparameters kpub = kp.getpublickey();
        do
        {
            r++;
            if (r > params.signfailtolerance)
            {
                throw new illegalstateexception("signing failed: too many retries (max=" + params.signfailtolerance + ")");
            }
            i = createmsgrep(msghash, r);
            s = sign(i, kp);
        }
        while (!verify(i, s, kpub.h));

        byte[] rawsig = s.tobinary(params.q);
        bytebuffer sbuf = bytebuffer.allocate(rawsig.length + 4);
        sbuf.put(rawsig);
        sbuf.putint(r);
        return sbuf.array();
    }

    private integerpolynomial sign(integerpolynomial i, ntrusigningprivatekeyparameters kp)
    {
        int n = params.n;
        int q = params.q;
        int perturbationbases = params.b;

        ntrusigningprivatekeyparameters kpriv = kp;
        ntrusigningpublickeyparameters kpub = kp.getpublickey();

        integerpolynomial s = new integerpolynomial(n);
        int iloop = perturbationbases;
        while (iloop >= 1)
        {
            polynomial f = kpriv.getbasis(iloop).f;
            polynomial fprime = kpriv.getbasis(iloop).fprime;

            integerpolynomial y = f.mult(i);
            y.div(q);
            y = fprime.mult(y);

            integerpolynomial x = fprime.mult(i);
            x.div(q);
            x = f.mult(x);

            integerpolynomial si = y;
            si.sub(x);
            s.add(si);

            integerpolynomial hi = (integerpolynomial)kpriv.getbasis(iloop).h.clone();
            if (iloop > 1)
            {
                hi.sub(kpriv.getbasis(iloop - 1).h);
            }
            else
            {
                hi.sub(kpub.h);
            }
            i = si.mult(hi, q);

            iloop--;
        }

        polynomial f = kpriv.getbasis(0).f;
        polynomial fprime = kpriv.getbasis(0).fprime;

        integerpolynomial y = f.mult(i);
        y.div(q);
        y = fprime.mult(y);

        integerpolynomial x = fprime.mult(i);
        x.div(q);
        x = f.mult(x);

        y.sub(x);
        s.add(y);
        s.modpositive(q);
        return s;
    }

    /**
     * verifies a signature for any data previously added via {@link #update(byte[], int, int)}.
     *
     * @param sig a signature
     * @return whether the signature is valid
     * @throws illegalstateexception if <code>initverify</code> was not called
     */
    public boolean verifysignature(byte[] sig)
    {
        if (hashalg == null || verificationkey == null)
        {
            throw new illegalstateexception("call initverify first!");
        }

        byte[] msghash = new byte[hashalg.getdigestsize()];

        hashalg.dofinal(msghash, 0);

        return verifyhash(msghash, sig, verificationkey);
    }

    private boolean verifyhash(byte[] msghash, byte[] sig, ntrusigningpublickeyparameters pub)
    {
        bytebuffer sbuf = bytebuffer.wrap(sig);
        byte[] rawsig = new byte[sig.length - 4];
        sbuf.get(rawsig);
        integerpolynomial s = integerpolynomial.frombinary(rawsig, params.n, params.q);
        int r = sbuf.getint();
        return verify(createmsgrep(msghash, r), s, pub.h);
    }

    private boolean verify(integerpolynomial i, integerpolynomial s, integerpolynomial h)
    {
        int q = params.q;
        double normboundsq = params.normboundsq;
        double betasq = params.betasq;

        integerpolynomial t = h.mult(s, q);
        t.sub(i);
        long centerednormsq = (long)(s.centerednormsq(q) + betasq * t.centerednormsq(q));
        return centerednormsq <= normboundsq;
    }

    protected integerpolynomial createmsgrep(byte[] msghash, int r)
    {
        int n = params.n;
        int q = params.q;

        int c = 31 - integer.numberofleadingzeros(q);
        int b = (c + 7) / 8;
        integerpolynomial i = new integerpolynomial(n);

        bytebuffer cbuf = bytebuffer.allocate(msghash.length + 4);
        cbuf.put(msghash);
        cbuf.putint(r);
        ntrusignerprng prng = new ntrusignerprng(cbuf.array(), params.hashalg);

        for (int t = 0; t < n; t++)
        {
            byte[] o = prng.nextbytes(b);
            int hi = o[o.length - 1];
            hi >>= 8 * b - c;
            hi <<= 8 * b - c;
            o[o.length - 1] = (byte)hi;

            bytebuffer obuf = bytebuffer.allocate(4);
            obuf.put(o);
            obuf.rewind();
            // reverse byte order so it matches the endianness of java ints
            i.coeffs[t] = integer.reversebytes(obuf.getint());
        }
        return i;
    }
}
