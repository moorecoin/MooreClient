package org.ripple.bouncycastle.crypto.digests;

import org.ripple.bouncycastle.crypto.extendeddigest;
import org.ripple.bouncycastle.util.arrays;

/**
 * implementation of sha-3 based on following keccaknistinterface.c from http://keccak.noekeon.org/
 * <p/>
 * following the naming conventions used in the c source code to enable easy review of the implementation.
 */
public class sha3digest
    implements extendeddigest
{
    private static long[] keccakroundconstants = keccakinitializeroundconstants();

    private static int[] keccakrhooffsets = keccakinitializerhooffsets();

    private static long[] keccakinitializeroundconstants()
    {
        long[] keccakroundconstants = new long[24];
        byte[] lfsrstate = new byte[1];

        lfsrstate[0] = 0x01;
        int i, j, bitposition;

        for (i = 0; i < 24; i++)
        {
            keccakroundconstants[i] = 0;
            for (j = 0; j < 7; j++)
            {
                bitposition = (1 << j) - 1;
                if (lfsr86540(lfsrstate))
                {
                    keccakroundconstants[i] ^= 1l << bitposition;
                }
            }
        }

        return keccakroundconstants;
    }

    private static boolean lfsr86540(byte[] lfsr)
    {
        boolean result = (((lfsr[0]) & 0x01) != 0);
        if (((lfsr[0]) & 0x80) != 0)
        {
            lfsr[0] = (byte)(((lfsr[0]) << 1) ^ 0x71);
        }
        else
        {
            lfsr[0] <<= 1;
        }

        return result;
    }

    private static int[] keccakinitializerhooffsets()
    {
        int[] keccakrhooffsets = new int[25];
        int x, y, t, newx, newy;

        keccakrhooffsets[(((0) % 5) + 5 * ((0) % 5))] = 0;
        x = 1;
        y = 0;
        for (t = 0; t < 24; t++)
        {
            keccakrhooffsets[(((x) % 5) + 5 * ((y) % 5))] = ((t + 1) * (t + 2) / 2) % 64;
            newx = (0 * x + 1 * y) % 5;
            newy = (2 * x + 3 * y) % 5;
            x = newx;
            y = newy;
        }

        return keccakrhooffsets;
    }

    private byte[] state = new byte[(1600 / 8)];
    private byte[] dataqueue = new byte[(1536 / 8)];
    private int rate;
    private int bitsinqueue;
    private int fixedoutputlength;
    private boolean squeezing;
    private int bitsavailableforsqueezing;
    private byte[] chunk;
    private byte[] onebyte;

    private void cleardataqueuesection(int off, int len)
    {
        for (int i = off; i != off + len; i++)
        {
            dataqueue[i] = 0;
        }
    }

    public sha3digest()
    {
        init(0);
    }

    public sha3digest(int bitlength)
    {
        init(bitlength);
    }

    public sha3digest(sha3digest source) {
        system.arraycopy(source.state, 0, this.state, 0, source.state.length);
        system.arraycopy(source.dataqueue, 0, this.dataqueue, 0, source.dataqueue.length);
        this.rate = source.rate;
        this.bitsinqueue = source.bitsinqueue;
        this.fixedoutputlength = source.fixedoutputlength;
        this.squeezing = source.squeezing;
        this.bitsavailableforsqueezing = source.bitsavailableforsqueezing;
        this.chunk = arrays.clone(source.chunk);
        this.onebyte = arrays.clone(source.onebyte);
    }

    public string getalgorithmname()
    {
        return "sha3-" + fixedoutputlength;
    }

    public int getdigestsize()
    {
        return fixedoutputlength / 8;
    }

    public void update(byte in)
    {
        onebyte[0] = in;

        doupdate(onebyte, 0, 8l);
    }

    public void update(byte[] in, int inoff, int len)
    {
        doupdate(in, inoff, len * 8l);
    }

    public int dofinal(byte[] out, int outoff)
    {
        squeeze(out, outoff, fixedoutputlength);

        reset();

        return getdigestsize();
    }

    public void reset()
    {
        init(fixedoutputlength);
    }

    /**
     * return the size of block that the compression function is applied to in bytes.
     *
     * @return internal byte length of a block.
     */
    public int getbytelength()
    {
        return rate / 8;
    }

    private void init(int bitlength)
    {
        switch (bitlength)
        {
        case 0:
        case 288:
            initsponge(1024, 576);
            break;
        case 224:
            initsponge(1152, 448);
            break;
        case 256:
            initsponge(1088, 512);
            break;
        case 384:
            initsponge(832, 768);
            break;
        case 512:
            initsponge(576, 1024);
            break;
        default:
            throw new illegalargumentexception("bitlength must be one of 224, 256, 384, or 512.");
        }
    }

    private void doupdate(byte[] data, int off, long databitlen)
    {
        if ((databitlen % 8) == 0)
        {
            absorb(data, off, databitlen);
        }
        else
        {
            absorb(data, off, databitlen - (databitlen % 8));

            byte[] lastbyte = new byte[1];

            lastbyte[0] = (byte)(data[off + (int)(databitlen / 8)] >> (8 - (databitlen % 8)));
            absorb(lastbyte, off, databitlen % 8);
        }
    }

    private void initsponge(int rate, int capacity)
    {
        if (rate + capacity != 1600)
        {
            throw new illegalstateexception("rate + capacity != 1600");
        }
        if ((rate <= 0) || (rate >= 1600) || ((rate % 64) != 0))
        {
            throw new illegalstateexception("invalid rate value");
        }

        this.rate = rate;
        // this is never read, need to check to see why we want to save it
        //  this.capacity = capacity;
        this.fixedoutputlength = 0;
        arrays.fill(this.state, (byte)0);
        arrays.fill(this.dataqueue, (byte)0);
        this.bitsinqueue = 0;
        this.squeezing = false;
        this.bitsavailableforsqueezing = 0;
        this.fixedoutputlength = capacity / 2;
        this.chunk = new byte[rate / 8];
        this.onebyte = new byte[1];
    }

    private void absorbqueue()
    {
        keccakabsorb(state, dataqueue, rate / 8);

        bitsinqueue = 0;
    }

    private void absorb(byte[] data, int off, long databitlen)
    {
        long i, j, wholeblocks;

        if ((bitsinqueue % 8) != 0)
        {
            throw new illegalstateexception("attempt to absorb with odd length queue.");
        }
        if (squeezing)
        {
            throw new illegalstateexception("attempt to absorb while squeezing.");
        }

        i = 0;
        while (i < databitlen)
        {
            if ((bitsinqueue == 0) && (databitlen >= rate) && (i <= (databitlen - rate)))
            {
                wholeblocks = (databitlen - i) / rate;

                for (j = 0; j < wholeblocks; j++)
                {
                    system.arraycopy(data, (int)(off + (i / 8) + (j * chunk.length)), chunk, 0, chunk.length);

//                            displayintermediatevalues.displaybytes(1, "block to be absorbed", curdata, rate / 8);

                    keccakabsorb(state, chunk, chunk.length);
                }

                i += wholeblocks * rate;
            }
            else
            {
                int partialblock = (int)(databitlen - i);
                if (partialblock + bitsinqueue > rate)
                {
                    partialblock = rate - bitsinqueue;
                }
                int partialbyte = partialblock % 8;
                partialblock -= partialbyte;
                system.arraycopy(data, off + (int)(i / 8), dataqueue, bitsinqueue / 8, partialblock / 8);

                bitsinqueue += partialblock;
                i += partialblock;
                if (bitsinqueue == rate)
                {
                    absorbqueue();
                }
                if (partialbyte > 0)
                {
                    int mask = (1 << partialbyte) - 1;
                    dataqueue[bitsinqueue / 8] = (byte)(data[off + ((int)(i / 8))] & mask);
                    bitsinqueue += partialbyte;
                    i += partialbyte;
                }
            }
        }
    }

    private void padandswitchtosqueezingphase()
    {
        if (bitsinqueue + 1 == rate)
        {
            dataqueue[bitsinqueue / 8] |= 1 << (bitsinqueue % 8);
            absorbqueue();
            cleardataqueuesection(0, rate / 8);
        }
        else
        {
            cleardataqueuesection((bitsinqueue + 7) / 8, rate / 8 - (bitsinqueue + 7) / 8);
            dataqueue[bitsinqueue / 8] |= 1 << (bitsinqueue % 8);
        }
        dataqueue[(rate - 1) / 8] |= 1 << ((rate - 1) % 8);
        absorbqueue();


//            displayintermediatevalues.displaytext(1, "--- switching to squeezing phase ---");


        if (rate == 1024)
        {
            keccakextract1024bits(state, dataqueue);
            bitsavailableforsqueezing = 1024;
        }
        else

        {
            keccakextract(state, dataqueue, rate / 64);
            bitsavailableforsqueezing = rate;
        }

//            displayintermediatevalues.displaybytes(1, "block available for squeezing", dataqueue, bitsavailableforsqueezing / 8);

        squeezing = true;
    }

    private void squeeze(byte[] output, int offset, long outputlength)
    {
        long i;
        int partialblock;

        if (!squeezing)
        {
            padandswitchtosqueezingphase();
        }
        if ((outputlength % 8) != 0)
        {
            throw new illegalstateexception("outputlength not a multiple of 8");
        }

        i = 0;
        while (i < outputlength)
        {
            if (bitsavailableforsqueezing == 0)
            {
                keccakpermutation(state);

                if (rate == 1024)
                {
                    keccakextract1024bits(state, dataqueue);
                    bitsavailableforsqueezing = 1024;
                }
                else

                {
                    keccakextract(state, dataqueue, rate / 64);
                    bitsavailableforsqueezing = rate;
                }

//                    displayintermediatevalues.displaybytes(1, "block available for squeezing", dataqueue, bitsavailableforsqueezing / 8);

            }
            partialblock = bitsavailableforsqueezing;
            if ((long)partialblock > outputlength - i)
            {
                partialblock = (int)(outputlength - i);
            }

            system.arraycopy(dataqueue, (rate - bitsavailableforsqueezing) / 8, output, offset + (int)(i / 8), partialblock / 8);
            bitsavailableforsqueezing -= partialblock;
            i += partialblock;
        }
    }

    private void frombytestowords(long[] stateaswords, byte[] state)
    {
        for (int i = 0; i < (1600 / 64); i++)
        {
            stateaswords[i] = 0;
            int index = i * (64 / 8);
            for (int j = 0; j < (64 / 8); j++)
            {
                stateaswords[i] |= ((long)state[index + j] & 0xff) << ((8 * j));
            }
        }
    }

    private void fromwordstobytes(byte[] state, long[] stateaswords)
    {
        for (int i = 0; i < (1600 / 64); i++)
        {
            int index = i * (64 / 8);
            for (int j = 0; j < (64 / 8); j++)
            {
                state[index + j] = (byte)((stateaswords[i] >>> ((8 * j))) & 0xff);
            }
        }
    }

    private void keccakpermutation(byte[] state)
    {
        long[] longstate = new long[state.length / 8];

        frombytestowords(longstate, state);

//        displayintermediatevalues.displaystateasbytes(1, "input of permutation", longstate);

        keccakpermutationonwords(longstate);

//        displayintermediatevalues.displaystateasbytes(1, "state after permutation", longstate);

        fromwordstobytes(state, longstate);
    }

    private void keccakpermutationafterxor(byte[] state, byte[] data, int datalengthinbytes)
    {
        int i;

        for (i = 0; i < datalengthinbytes; i++)
        {
            state[i] ^= data[i];
        }

        keccakpermutation(state);
    }

    private void keccakpermutationonwords(long[] state)
    {
        int i;

//        displayintermediatevalues.displaystateas64bitwords(3, "same, with lanes as 64-bit words", state);

        for (i = 0; i < 24; i++)
        {
//            displayintermediatevalues.displayroundnumber(3, i);

            theta(state);
//            displayintermediatevalues.displaystateas64bitwords(3, "after theta", state);

            rho(state);
//            displayintermediatevalues.displaystateas64bitwords(3, "after rho", state);

            pi(state);
//            displayintermediatevalues.displaystateas64bitwords(3, "after pi", state);

            chi(state);
//            displayintermediatevalues.displaystateas64bitwords(3, "after chi", state);

            iota(state, i);
//            displayintermediatevalues.displaystateas64bitwords(3, "after iota", state);
        }
    }

    long[] c = new long[5];

    private void theta(long[] a)
    {
        for (int x = 0; x < 5; x++)
        {
            c[x] = 0;
            for (int y = 0; y < 5; y++)
            {
                c[x] ^= a[x + 5 * y];
            }
        }
        for (int x = 0; x < 5; x++)
        {
            long dx = ((((c[(x + 1) % 5]) << 1) ^ ((c[(x + 1) % 5]) >>> (64 - 1)))) ^ c[(x + 4) % 5];
            for (int y = 0; y < 5; y++)
            {
                a[x + 5 * y] ^= dx;
            }
        }
    }

    private void rho(long[] a)
    {
        for (int x = 0; x < 5; x++)
        {
            for (int y = 0; y < 5; y++)
            {
                int index = x + 5 * y;
                a[index] = ((keccakrhooffsets[index] != 0) ? (((a[index]) << keccakrhooffsets[index]) ^ ((a[index]) >>> (64 - keccakrhooffsets[index]))) : a[index]);
            }
        }
    }

    long[] tempa = new long[25];

    private void pi(long[] a)
    {
        system.arraycopy(a, 0, tempa, 0, tempa.length);

        for (int x = 0; x < 5; x++)
        {
            for (int y = 0; y < 5; y++)
            {
                a[y + 5 * ((2 * x + 3 * y) % 5)] = tempa[x + 5 * y];
            }
        }
    }

    long[] chic = new long[5];

    private void chi(long[] a)
    {
        for (int y = 0; y < 5; y++)
        {
            for (int x = 0; x < 5; x++)
            {
                chic[x] = a[x + 5 * y] ^ ((~a[(((x + 1) % 5) + 5 * y)]) & a[(((x + 2) % 5) + 5 * y)]);
            }
            for (int x = 0; x < 5; x++)
            {
                a[x + 5 * y] = chic[x];
            }
        }
    }

    private void iota(long[] a, int indexround)
    {
        a[(((0) % 5) + 5 * ((0) % 5))] ^= keccakroundconstants[indexround];
    }

    private void keccakabsorb(byte[] bytestate, byte[] data, int datainbytes)
    {
        keccakpermutationafterxor(bytestate, data, datainbytes);
    }


    private void keccakextract1024bits(byte[] bytestate, byte[] data)
    {
        system.arraycopy(bytestate, 0, data, 0, 128);
    }


    private void keccakextract(byte[] bytestate, byte[] data, int lanecount)
    {
        system.arraycopy(bytestate, 0, data, 0, lanecount * 8);
    }
}
