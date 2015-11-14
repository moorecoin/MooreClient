package org.ripple.bouncycastle.pqc.crypto.gmss;

import org.ripple.bouncycastle.crypto.digest;
import org.ripple.bouncycastle.pqc.crypto.gmss.util.gmssrandom;
import org.ripple.bouncycastle.util.arrays;
import org.ripple.bouncycastle.util.encoders.hex;


/**
 * this class implements the distributed computation of the public key of the
 * winternitz one-time signature scheme (otss). the class is used by the gmss
 * classes for calculation of upcoming leafs.
 */
public class gmssleaf
{

    /**
     * the hash function used by the ots and the prng
     */
    private digest messdigestots;

    /**
     * the length of the message digest and private key
     */
    private int mdsize, keysize;

    /**
     * the source of randomness for ots private key generation
     */
    private gmssrandom gmssrandom;

    /**
     * byte array for distributed computation of the upcoming leaf
     */
    private byte[] leaf;

    /**
     * byte array for storing the concatenated hashes of private key parts
     */
    private byte[] conchashs;

    /**
     * indices for distributed computation
     */
    private int i, j;

    /**
     * storing 2^w
     */
    private int two_power_w;

    /**
     * winternitz parameter w
     */
    private int w;

    /**
     * the amount of distributed computation steps when updateleaf is called
     */
    private int steps;

    /**
     * the internal seed
     */
    private byte[] seed;

    /**
     * the ots privatekey parts
     */
    byte[] privatekeyots;

    /**
     * this constructor regenerates a prior gmssleaf object
     *
     * @param digest   an array of strings, containing the name of the used hash
     *                 function and prng and the name of the corresponding
     *                 provider
     * @param otsindex status bytes
     * @param numleafs status ints
     */
    public gmssleaf(digest digest, byte[][] otsindex, int[] numleafs)
    {
        this.i = numleafs[0];
        this.j = numleafs[1];
        this.steps = numleafs[2];
        this.w = numleafs[3];

        messdigestots = digest;

        gmssrandom = new gmssrandom(messdigestots);

        // calulate keysize for private key and the help array
        mdsize = messdigestots.getdigestsize();
        int mdsizebit = mdsize << 3;
        int messagesize = (int)math.ceil((double)(mdsizebit) / (double)w);
        int checksumsize = getlog((messagesize << w) + 1);
        this.keysize = messagesize
            + (int)math.ceil((double)checksumsize / (double)w);
        this.two_power_w = 1 << w;

        // calculate steps
        // ((2^w)-1)*keysize + keysize + 1 / (2^h -1)

        // initialize arrays
        this.privatekeyots = otsindex[0];
        this.seed = otsindex[1];
        this.conchashs = otsindex[2];
        this.leaf = otsindex[3];
    }

    /**
     * the constructor precomputes some needed variables for distributed leaf
     * calculation
     *
     * @param digest     an array of strings, containing the digest of the used hash
     *                 function and prng and the digest of the corresponding
     *                 provider
     * @param w        the winterniz parameter of that tree the leaf is computed
     *                 for
     * @param numleafs the number of leafs of the tree from where the distributed
     *                 computation is called
     */
    gmssleaf(digest digest, int w, int numleafs)
    {
        this.w = w;

        messdigestots = digest;

        gmssrandom = new gmssrandom(messdigestots);

        // calulate keysize for private key and the help array
        mdsize = messdigestots.getdigestsize();
        int mdsizebit = mdsize << 3;
        int messagesize = (int)math.ceil((double)(mdsizebit) / (double)w);
        int checksumsize = getlog((messagesize << w) + 1);
        this.keysize = messagesize
            + (int)math.ceil((double)checksumsize / (double)w);
        this.two_power_w = 1 << w;

        // calculate steps
        // ((2^w)-1)*keysize + keysize + 1 / (2^h -1)
        this.steps = (int)math
            .ceil((double)(((1 << w) - 1) * keysize + 1 + keysize)
                / (double)(numleafs));

        // initialize arrays
        this.seed = new byte[mdsize];
        this.leaf = new byte[mdsize];
        this.privatekeyots = new byte[mdsize];
        this.conchashs = new byte[mdsize * keysize];
    }

    public gmssleaf(digest digest, int w, int numleafs, byte[] seed0)
    {
        this.w = w;

        messdigestots = digest;

        gmssrandom = new gmssrandom(messdigestots);

        // calulate keysize for private key and the help array
        mdsize = messdigestots.getdigestsize();
        int mdsizebit = mdsize << 3;
        int messagesize = (int)math.ceil((double)(mdsizebit) / (double)w);
        int checksumsize = getlog((messagesize << w) + 1);
        this.keysize = messagesize
            + (int)math.ceil((double)checksumsize / (double)w);
        this.two_power_w = 1 << w;

        // calculate steps
        // ((2^w)-1)*keysize + keysize + 1 / (2^h -1)
        this.steps = (int)math
            .ceil((double)(((1 << w) - 1) * keysize + 1 + keysize)
                / (double)(numleafs));

        // initialize arrays
        this.seed = new byte[mdsize];
        this.leaf = new byte[mdsize];
        this.privatekeyots = new byte[mdsize];
        this.conchashs = new byte[mdsize * keysize];

        initleafcalc(seed0);
    }

    private gmssleaf(gmssleaf original)
    {
        this.messdigestots = original.messdigestots;
        this.mdsize = original.mdsize;
        this.keysize = original.keysize;
        this.gmssrandom = original.gmssrandom;
        this.leaf = arrays.clone(original.leaf);
        this.conchashs = arrays.clone(original.conchashs);
        this.i = original.i;
        this.j = original.j;
        this.two_power_w = original.two_power_w;
        this.w = original.w;
        this.steps = original.steps;
        this.seed = arrays.clone(original.seed);
        this.privatekeyots = arrays.clone(original.privatekeyots);
    }

    /**
     * initialize the distributed leaf calculation reset i,j and compute otsseed
     * with seed0
     *
     * @param seed0 the starting seed
     */
    // todo: this really looks like it should be either always called from a constructor or nextleaf.
    void initleafcalc(byte[] seed0)
    {
        this.i = 0;
        this.j = 0;
        byte[] dummy = new byte[mdsize];
        system.arraycopy(seed0, 0, dummy, 0, seed.length);
        this.seed = gmssrandom.nextseed(dummy);
    }

    gmssleaf nextleaf()
    {
        gmssleaf nextleaf = new gmssleaf(this);

        nextleaf.updateleafcalc();

        return nextleaf;
    }

    /**
     * processes <code>steps</code> steps of distributed leaf calculation
     *
     * @return true if leaf is completed, else false
     */
    private void updateleafcalc()
    {
         byte[] buf = new byte[messdigestots.getdigestsize()];

        // steps times do
        // todo: this really needs to be looked at, the 10000 has been added as
        // prior to this the leaf value always ended up as zeros.
        for (int s = 0; s < steps + 10000; s++)
        {
            if (i == keysize && j == two_power_w - 1)
            { // [3] at last hash the
                // concatenation
                messdigestots.update(conchashs, 0, conchashs.length);
                leaf = new byte[messdigestots.getdigestsize()];
                messdigestots.dofinal(leaf, 0);
                return;
            }
            else if (i == 0 || j == two_power_w - 1)
            { // [1] at the
                // beginning and
                // when [2] is
                // finished: get the
                // next private key
                // part
                i++;
                j = 0;
                // get next privkey part
                this.privatekeyots = gmssrandom.nextseed(seed);
            }
            else
            { // [2] hash the privkey part
                messdigestots.update(privatekeyots, 0, privatekeyots.length);
                privatekeyots = buf;
                messdigestots.dofinal(privatekeyots, 0);
                j++;
                if (j == two_power_w - 1)
                { // after w hashes add to the
                    // concatenated array
                    system.arraycopy(privatekeyots, 0, conchashs, mdsize
                        * (i - 1), mdsize);
                }
            }
        }

       throw new illegalstateexception("unable to updateleaf in steps: " + steps + " " + i + " " + j);
    }

    /**
     * returns the leaf value.
     *
     * @return the leaf value
     */
    public byte[] getleaf()
    {
        return arrays.clone(leaf);
    }

    /**
     * this method returns the least integer that is greater or equal to the
     * logarithm to the base 2 of an integer <code>intvalue</code>.
     *
     * @param intvalue an integer
     * @return the least integer greater or equal to the logarithm to the base 2
     *         of <code>intvalue</code>
     */
    private int getlog(int intvalue)
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
     * returns the status byte array used by the gmssprivatekeyasn.1 class
     *
     * @return the status bytes
     */
    public byte[][] getstatbyte()
    {

        byte[][] statbyte = new byte[4][];
        statbyte[0] = new byte[mdsize];
        statbyte[1] = new byte[mdsize];
        statbyte[2] = new byte[mdsize * keysize];
        statbyte[3] = new byte[mdsize];
        statbyte[0] = privatekeyots;
        statbyte[1] = seed;
        statbyte[2] = conchashs;
        statbyte[3] = leaf;

        return statbyte;
    }

    /**
     * returns the status int array used by the gmssprivatekeyasn.1 class
     *
     * @return the status ints
     */
    public int[] getstatint()
    {

        int[] statint = new int[4];
        statint[0] = i;
        statint[1] = j;
        statint[2] = steps;
        statint[3] = w;
        return statint;
    }

    /**
     * returns a string representation of the main part of this element
     *
     * @return a string representation of the main part of this element
     */
    public string tostring()
    {
        string out = "";

        for (int i = 0; i < 4; i++)
        {
            out = out + this.getstatint()[i] + " ";
        }
        out = out + " " + this.mdsize + " " + this.keysize + " "
            + this.two_power_w + " ";

        byte[][] temp = this.getstatbyte();
        for (int i = 0; i < 4; i++)
        {
            if (temp[i] != null)
            {
                out = out + new string(hex.encode(temp[i])) + " ";
            }
            else
            {
                out = out + "null ";
            }
        }
        return out;
    }
}
