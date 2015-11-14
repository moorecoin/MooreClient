package org.ripple.bouncycastle.crypto.macs;

import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.datalengthexception;
import org.ripple.bouncycastle.crypto.mac;
import org.ripple.bouncycastle.crypto.params.keyparameter;
import org.ripple.bouncycastle.crypto.util.pack;
import org.ripple.bouncycastle.util.arrays;

/**
 * implementation of siphash as specified in "siphash: a fast short-input prf", by jean-philippe
 * aumasson and daniel j. bernstein (https://131002.net/siphash/siphash.pdf).
 * <p/>
 * "siphash is a family of prfs siphash-c-d where the integer parameters c and d are the number of
 * compression rounds and the number of finalization rounds. a compression round is identical to a
 * finalization round and this round function is called sipround. given a 128-bit key k and a
 * (possibly empty) byte string m, siphash-c-d returns a 64-bit value..."
 */
public class siphash
    implements mac
{

    protected final int c, d;

    protected long k0, k1;
    protected long v0, v1, v2, v3, v4;

    protected byte[] buf = new byte[8];
    protected int bufpos = 0;
    protected int wordcount = 0;

    /**
     * siphash-2-4
     */
    public siphash()
    {
        // use of this confuses flow analyser on earlier jdks.
        this.c = 2;
        this.d = 4;
    }

    /**
     * siphash-c-d
     *
     * @param c the number of compression rounds
     * @param d the number of finalization rounds
     */
    public siphash(int c, int d)
    {
        this.c = c;
        this.d = d;
    }

    public string getalgorithmname()
    {
        return "siphash-" + c + "-" + d;
    }

    public int getmacsize()
    {
        return 8;
    }

    public void init(cipherparameters params)
        throws illegalargumentexception
    {
        if (!(params instanceof keyparameter))
        {
            throw new illegalargumentexception("'params' must be an instance of keyparameter");
        }
        keyparameter keyparameter = (keyparameter)params;
        byte[] key = keyparameter.getkey();
        if (key.length != 16)
        {
            throw new illegalargumentexception("'params' must be a 128-bit key");
        }

        this.k0 = pack.littleendiantolong(key, 0);
        this.k1 = pack.littleendiantolong(key, 8);

        reset();
    }

    public void update(byte input)
        throws illegalstateexception
    {

        buf[bufpos] = input;
        if (++bufpos == buf.length)
        {
            processmessageword();
            bufpos = 0;
        }
    }

    public void update(byte[] input, int offset, int length)
        throws datalengthexception,
        illegalstateexception
    {

        for (int i = 0; i < length; ++i)
        {
            buf[bufpos] = input[offset + i];
            if (++bufpos == buf.length)
            {
                processmessageword();
                bufpos = 0;
            }
        }
    }

    public long dofinal()
        throws datalengthexception, illegalstateexception
    {

        buf[7] = (byte)(((wordcount << 3) + bufpos) & 0xff);
        while (bufpos < 7)
        {
            buf[bufpos++] = 0;
        }

        processmessageword();

        v2 ^= 0xffl;

        applysiprounds(d);

        long result = v0 ^ v1 ^ v2 ^ v3;

        reset();

        return result;
    }

    public int dofinal(byte[] out, int outoff)
        throws datalengthexception, illegalstateexception
    {

        long result = dofinal();
        pack.longtolittleendian(result, out, outoff);
        return 8;
    }

    public void reset()
    {

        v0 = k0 ^ 0x736f6d6570736575l;
        v1 = k1 ^ 0x646f72616e646f6dl;
        v2 = k0 ^ 0x6c7967656e657261l;
        v3 = k1 ^ 0x7465646279746573l;

        arrays.fill(buf, (byte)0);
        bufpos = 0;
        wordcount = 0;
    }

    protected void processmessageword()
    {

        ++wordcount;
        long m = pack.littleendiantolong(buf, 0);
        v3 ^= m;
        applysiprounds(c);
        v0 ^= m;
    }

    protected void applysiprounds(int n)
    {
        for (int r = 0; r < n; ++r)
        {
            v0 += v1;
            v2 += v3;
            v1 = rotateleft(v1, 13);
            v3 = rotateleft(v3, 16);
            v1 ^= v0;
            v3 ^= v2;
            v0 = rotateleft(v0, 32);
            v2 += v1;
            v0 += v3;
            v1 = rotateleft(v1, 17);
            v3 = rotateleft(v3, 21);
            v1 ^= v2;
            v3 ^= v0;
            v2 = rotateleft(v2, 32);
        }
    }

    protected static long rotateleft(long x, int n)
    {
        return (x << n) | (x >>> (64 - n));
    }
}
