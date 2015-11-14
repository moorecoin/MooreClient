package org.ripple.bouncycastle.pqc.crypto.gmss;

import org.ripple.bouncycastle.crypto.digest;
import org.ripple.bouncycastle.pqc.crypto.gmss.util.gmssrandom;
import org.ripple.bouncycastle.util.encoders.hex;


/**
 * this class implements the distributed signature generation of the winternitz
 * one-time signature scheme (otss), described in c.dods, n.p. smart, and m.
 * stam, "hash based digital signature schemes", lncs 3796, pages 96&#8211;115,
 * 2005. the class is used by the gmss classes.
 */
public class gmssrootsig
{

    /**
     * the hash function used by the ots
     */
    private digest messdigestots;

    /**
     * the length of the message digest and private key
     */
    private int mdsize, keysize;

    /**
     * the private key
     */
    private byte[] privatekeyots;

    /**
     * the message bytes
     */
    private byte[] hash;

    /**
     * the signature bytes
     */
    private byte[] sign;

    /**
     * the winternitz parameter
     */
    private int w;

    /**
     * the source of randomness for ots private key generation
     */
    private gmssrandom gmssrandom;

    /**
     * sizes of the message
     */
    private int messagesize;

    /**
     * some precalculated values
     */
    private int k;

    /**
     * some variables for storing the actual status of distributed signing
     */
    private int r, test, counter, ii;

    /**
     * variables for storing big numbers for the actual status of distributed
     * signing
     */
    private long test8, big8;

    /**
     * the necessary steps of each updatesign() call
     */
    private int steps;

    /**
     * the checksum part
     */
    private int checksum;

    /**
     * the height of the tree
     */
    private int height;

    /**
     * the current intern otsseed
     */
    private byte[] seed;

    /**
     * this constructor regenerates a prior gmssrootsig object used by the
     * gmssprivatekeyasn.1 class
     *
     * @param digest     an array of strings, containing the digest of the used hash
     *                 function, the digest of the prgn and the names of the
     *                 corresponding providers
     * @param statbyte status byte array
     * @param statint  status int array
     */
    public gmssrootsig(digest digest, byte[][] statbyte, int[] statint)
    {
        messdigestots = digest;
        gmssrandom = new gmssrandom(messdigestots);

        this.counter = statint[0];
        this.test = statint[1];
        this.ii = statint[2];
        this.r = statint[3];
        this.steps = statint[4];
        this.keysize = statint[5];
        this.height = statint[6];
        this.w = statint[7];
        this.checksum = statint[8];

        this.mdsize = messdigestots.getdigestsize();

        this.k = (1 << w) - 1;

        int mdsizebit = mdsize << 3;
        this.messagesize = (int)math.ceil((double)(mdsizebit) / (double)w);

        this.privatekeyots = statbyte[0];
        this.seed = statbyte[1];
        this.hash = statbyte[2];

        this.sign = statbyte[3];

        this.test8 = ((statbyte[4][0] & 0xff))
            | ((long)(statbyte[4][1] & 0xff) << 8)
            | ((long)(statbyte[4][2] & 0xff) << 16)
            | ((long)(statbyte[4][3] & 0xff)) << 24
            | ((long)(statbyte[4][4] & 0xff)) << 32
            | ((long)(statbyte[4][5] & 0xff)) << 40
            | ((long)(statbyte[4][6] & 0xff)) << 48
            | ((long)(statbyte[4][7] & 0xff)) << 56;

        this.big8 = ((statbyte[4][8] & 0xff))
            | ((long)(statbyte[4][9] & 0xff) << 8)
            | ((long)(statbyte[4][10] & 0xff) << 16)
            | ((long)(statbyte[4][11] & 0xff)) << 24
            | ((long)(statbyte[4][12] & 0xff)) << 32
            | ((long)(statbyte[4][13] & 0xff)) << 40
            | ((long)(statbyte[4][14] & 0xff)) << 48
            | ((long)(statbyte[4][15] & 0xff)) << 56;
    }

    /**
     * the constructor generates the prng and initializes some variables
     *
     * @param digest   an array of strings, containing the digest of the used hash
     *               function, the digest of the prgn and the names of the
     *               corresponding providers
     * @param w      the winternitz parameter
     * @param height the heigth of the tree
     */
    public gmssrootsig(digest digest, int w, int height)
    {
        messdigestots = digest;
        gmssrandom = new gmssrandom(messdigestots);

        this.mdsize = messdigestots.getdigestsize();
        this.w = w;
        this.height = height;

        this.k = (1 << w) - 1;

        int mdsizebit = mdsize << 3;
        this.messagesize = (int)math.ceil((double)(mdsizebit) / (double)w);
    }

    /**
     * this method initializes the distributed sigature calculation. variables
     * are reseted and necessary steps are calculated
     *
     * @param seed0   the initial otsseed
     * @param message the massage which will be signed
     */
    public void initsign(byte[] seed0, byte[] message)
    {

        // create hash of message m
        this.hash = new byte[mdsize];
        messdigestots.update(message, 0, message.length);
        this.hash = new byte[messdigestots.getdigestsize()];
        messdigestots.dofinal(this.hash, 0);

        // variables for calculation of steps
        byte[] messpart = new byte[mdsize];
        system.arraycopy(hash, 0, messpart, 0, mdsize);
        int checkpart = 0;
        int sumh = 0;
        int checksumsize = getlog((messagesize << w) + 1);

        // ------- calculation of necessary steps ------
        if (8 % w == 0)
        {
            int dt = 8 / w;
            // message part
            for (int a = 0; a < mdsize; a++)
            {
                // count necessary hashs in 'sumh'
                for (int b = 0; b < dt; b++)
                {
                    sumh += messpart[a] & k;
                    messpart[a] = (byte)(messpart[a] >>> w);
                }
            }
            // checksum part
            this.checksum = (messagesize << w) - sumh;
            checkpart = checksum;
            // count necessary hashs in 'sumh'
            for (int b = 0; b < checksumsize; b += w)
            {
                sumh += checkpart & k;
                checkpart >>>= w;
            }
        } // end if ( 8 % w == 0 )
        else if (w < 8)
        {
            long big8;
            int ii = 0;
            int dt = mdsize / w;

            // first d*w bytes of hash (main message part)
            for (int i = 0; i < dt; i++)
            {
                big8 = 0;
                for (int j = 0; j < w; j++)
                {
                    big8 ^= (messpart[ii] & 0xff) << (j << 3);
                    ii++;
                }
                // count necessary hashs in 'sumh'
                for (int j = 0; j < 8; j++)
                {
                    sumh += (int)(big8 & k);
                    big8 >>>= w;
                }
            }
            // rest of message part
            dt = mdsize % w;
            big8 = 0;
            for (int j = 0; j < dt; j++)
            {
                big8 ^= (messpart[ii] & 0xff) << (j << 3);
                ii++;
            }
            dt <<= 3;
            // count necessary hashs in 'sumh'
            for (int j = 0; j < dt; j += w)
            {
                sumh += (int)(big8 & k);
                big8 >>>= w;
            }
            // checksum part
            this.checksum = (messagesize << w) - sumh;
            checkpart = checksum;
            // count necessary hashs in 'sumh'
            for (int i = 0; i < checksumsize; i += w)
            {
                sumh += checkpart & k;
                checkpart >>>= w;
            }
        }// end if(w<8)
        else if (w < 57)
        {
            long big8;
            int r = 0;
            int s, f, rest, ii;

            // first a*w bits of hash where a*w <= 8*mdsize < (a+1)*w (main
            // message part)
            while (r <= ((mdsize << 3) - w))
            {
                s = r >>> 3;
                rest = r % 8;
                r += w;
                f = (r + 7) >>> 3;
                big8 = 0;
                ii = 0;
                for (int j = s; j < f; j++)
                {
                    big8 ^= (messpart[j] & 0xff) << (ii << 3);
                    ii++;
                }
                big8 >>>= rest;
                // count necessary hashs in 'sumh'
                sumh += (big8 & k);

            }
            // rest of message part
            s = r >>> 3;
            if (s < mdsize)
            {
                rest = r % 8;
                big8 = 0;
                ii = 0;
                for (int j = s; j < mdsize; j++)
                {
                    big8 ^= (messpart[j] & 0xff) << (ii << 3);
                    ii++;
                }

                big8 >>>= rest;
                // count necessary hashs in 'sumh'
                sumh += (big8 & k);
            }
            // checksum part
            this.checksum = (messagesize << w) - sumh;
            checkpart = checksum;
            // count necessary hashs in 'sumh'
            for (int i = 0; i < checksumsize; i += w)
            {
                sumh += (checkpart & k);
                checkpart >>>= w;
            }
        }// end if(w<57)

        // calculate keysize
        this.keysize = messagesize
            + (int)math.ceil((double)checksumsize / (double)w);

        // calculate steps: 'keysize' times prng, 'sumh' times hashing,
        // (1<<height)-1 updatesign() calls
        this.steps = (int)math.ceil((double)(keysize + sumh)
            / (double)((1 << height)));
        // ----------------------------

        // reset variables
        this.sign = new byte[keysize * mdsize];
        this.counter = 0;
        this.test = 0;
        this.ii = 0;
        this.test8 = 0;
        this.r = 0;
        // define the private key messagesize
        this.privatekeyots = new byte[mdsize];
        // copy the seed
        this.seed = new byte[mdsize];
        system.arraycopy(seed0, 0, this.seed, 0, mdsize);

    }

    /**
     * this method performs <code>steps</code> steps of distributed signature
     * calculaion
     *
     * @return true if signature is generated completly, else false
     */
    public boolean updatesign()
    {
        // steps times do

        for (int s = 0; s < steps; s++)
        { // do 'step' times

            if (counter < keysize)
            { // generate the private key or perform
                // the next hash
                onestep();
            }
            if (counter == keysize)
            {// finish
                return true;
            }
        }

        return false; // leaf not finished yet
    }

    /**
     * @return the private ots key
     */
    public byte[] getsig()
    {

        return sign;
    }

    /**
     * @return the one-time signature of the message, generated step by step
     */
    private void onestep()
    {
        // -------- if (8 % w == 0) ----------
        if (8 % w == 0)
        {
            if (test == 0)
            {
                // get current otsprivatekey
                this.privatekeyots = gmssrandom.nextseed(seed);
                // system.arraycopy(privatekeyots, 0, hlp, 0, mdsize);

                if (ii < mdsize)
                { // for main message part
                    test = hash[ii] & k;
                    hash[ii] = (byte)(hash[ii] >>> w);
                }
                else
                { // for checksum part
                    test = checksum & k;
                    checksum >>>= w;
                }
            }
            else if (test > 0)
            { // hash the private key 'test' times (on
                // time each step)
                messdigestots.update(privatekeyots, 0, privatekeyots.length);
                privatekeyots = new byte[messdigestots.getdigestsize()];
                messdigestots.dofinal(privatekeyots, 0);
                test--;
            }
            if (test == 0)
            { // if all hashes done copy result to siganture
                // array
                system.arraycopy(privatekeyots, 0, sign, counter * mdsize,
                    mdsize);
                counter++;

                if (counter % (8 / w) == 0)
                { // raise array index for main
                    // massage part
                    ii++;
                }
            }

        }// ----- end if (8 % w == 0) -----
        // ---------- if ( w < 8 ) ----------------
        else if (w < 8)
        {

            if (test == 0)
            {
                if (counter % 8 == 0 && ii < mdsize)
                { // after every 8th "add
                    // to signature"-step
                    big8 = 0;
                    if (counter < ((mdsize / w) << 3))
                    {// main massage
                        // (generate w*8 bits
                        // every time) part
                        for (int j = 0; j < w; j++)
                        {
                            big8 ^= (hash[ii] & 0xff) << (j << 3);
                            ii++;
                        }
                    }
                    else
                    { // rest of massage part (once)
                        for (int j = 0; j < mdsize % w; j++)
                        {
                            big8 ^= (hash[ii] & 0xff) << (j << 3);
                            ii++;
                        }
                    }
                }
                if (counter == messagesize)
                { // checksum part (once)
                    big8 = checksum;
                }

                test = (int)(big8 & k);
                // generate current otsprivatekey
                this.privatekeyots = gmssrandom.nextseed(seed);
                // system.arraycopy(privatekeyots, 0, hlp, 0, mdsize);

            }
            else if (test > 0)
            { // hash the private key 'test' times (on
                // time each step)
                messdigestots.update(privatekeyots, 0, privatekeyots.length);
                privatekeyots = new byte[messdigestots.getdigestsize()];
                messdigestots.dofinal(privatekeyots, 0);
                test--;
            }
            if (test == 0)
            { // if all hashes done copy result to siganture
                // array
                system.arraycopy(privatekeyots, 0, sign, counter * mdsize,
                    mdsize);
                big8 >>>= w;
                counter++;
            }

        }// ------- end if(w<8)--------------------------------
        // --------- if w < 57 -----------------------------
        else if (w < 57)
        {

            if (test8 == 0)
            {
                int s, f, rest;
                big8 = 0;
                ii = 0;
                rest = r % 8;
                s = r >>> 3;
                // --- message part---
                if (s < mdsize)
                {
                    if (r <= ((mdsize << 3) - w))
                    { // first message part
                        r += w;
                        f = (r + 7) >>> 3;
                    }
                    else
                    { // rest of message part (once)
                        f = mdsize;
                        r += w;
                    }
                    // generate long 'big8' with minimum w next bits of the
                    // message array
                    for (int i = s; i < f; i++)
                    {
                        big8 ^= (hash[i] & 0xff) << (ii << 3);
                        ii++;
                    }
                    // delete bits on the right side, which were used already by
                    // the last loop
                    big8 >>>= rest;
                    test8 = (big8 & k);
                }
                // --- checksum part
                else
                {
                    test8 = (checksum & k);
                    checksum >>>= w;
                }
                // generate current otsprivatekey
                this.privatekeyots = gmssrandom.nextseed(seed);
                // system.arraycopy(privatekeyots, 0, hlp, 0, mdsize);

            }
            else if (test8 > 0)
            { // hash the private key 'test' times (on
                // time each step)
                messdigestots.update(privatekeyots, 0, privatekeyots.length);
                privatekeyots = new byte[messdigestots.getdigestsize()];
                messdigestots.dofinal(privatekeyots, 0);
                test8--;
            }
            if (test8 == 0)
            { // if all hashes done copy result to siganture
                // array
                system.arraycopy(privatekeyots, 0, sign, counter * mdsize,
                    mdsize);
                counter++;
            }

        }
    }

    /**
     * this method returns the least integer that is greater or equal to the
     * logarithm to the base 2 of an integer <code>intvalue</code>.
     *
     * @param intvalue an integer
     * @return the least integer greater or equal to the logarithm to the base 2
     *         of <code>intvalue</code>
     */
    public int getlog(int intvalue)
    {
        int log = 1;
        int i = 2;
        while (i < intvalue)
        {
            i <<= 1;
            log++;
        }
        return log;
    }

    /**
     * this method returns the status byte array
     *
     * @return statbytes
     */
    public byte[][] getstatbyte()
    {

        byte[][] statbyte = new byte[5][mdsize];
        statbyte[0] = privatekeyots;
        statbyte[1] = seed;
        statbyte[2] = hash;
        statbyte[3] = sign;
        statbyte[4] = this.getstatlong();

        return statbyte;
    }

    /**
     * this method returns the status int array
     *
     * @return statint
     */
    public int[] getstatint()
    {
        int[] statint = new int[9];
        statint[0] = counter;
        statint[1] = test;
        statint[2] = ii;
        statint[3] = r;
        statint[4] = steps;
        statint[5] = keysize;
        statint[6] = height;
        statint[7] = w;
        statint[8] = checksum;
        return statint;
    }

    /**
     * converts the long parameters into byte arrays to store it in
     * statbyte-array
     */
    public byte[] getstatlong()
    {
        byte[] bytes = new byte[16];

        bytes[0] = (byte)((test8) & 0xff);
        bytes[1] = (byte)((test8 >> 8) & 0xff);
        bytes[2] = (byte)((test8 >> 16) & 0xff);
        bytes[3] = (byte)((test8 >> 24) & 0xff);
        bytes[4] = (byte)((test8) >> 32 & 0xff);
        bytes[5] = (byte)((test8 >> 40) & 0xff);
        bytes[6] = (byte)((test8 >> 48) & 0xff);
        bytes[7] = (byte)((test8 >> 56) & 0xff);

        bytes[8] = (byte)((big8) & 0xff);
        bytes[9] = (byte)((big8 >> 8) & 0xff);
        bytes[10] = (byte)((big8 >> 16) & 0xff);
        bytes[11] = (byte)((big8 >> 24) & 0xff);
        bytes[12] = (byte)((big8) >> 32 & 0xff);
        bytes[13] = (byte)((big8 >> 40) & 0xff);
        bytes[14] = (byte)((big8 >> 48) & 0xff);
        bytes[15] = (byte)((big8 >> 56) & 0xff);

        return bytes;
    }

    /**
     * returns a string representation of the instance
     *
     * @return a string representation of the instance
     */
    public string tostring()
    {
        string out = "" + this.big8 + "  ";
        int[] statint = new int[9];
        statint = this.getstatint();
        byte[][] statbyte = new byte[5][mdsize];
        statbyte = this.getstatbyte();
        for (int i = 0; i < 9; i++)
        {
            out = out + statint[i] + " ";
        }
        for (int i = 0; i < 5; i++)
        {
            out = out + new string(hex.encode(statbyte[i])) + " ";
        }

        return out;
    }

}
