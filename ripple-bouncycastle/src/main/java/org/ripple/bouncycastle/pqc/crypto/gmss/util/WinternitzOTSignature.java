package org.ripple.bouncycastle.pqc.crypto.gmss.util;

import org.ripple.bouncycastle.crypto.digest;

/**
 * this class implements key pair generation and signature generation of the
 * winternitz one-time signature scheme (otss), described in c.dods, n.p. smart,
 * and m. stam, "hash based digital signature schemes", lncs 3796, pages
 * 96&#8211;115, 2005. the class is used by the gmss classes.
 */

public class winternitzotsignature
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
     * an array of strings, containing the name of the used hash function, the
     * name of the prgn and the names of the corresponding providers
     */
    // private string[] name = new string[2];
    /**
     * the private key
     */
    private byte[][] privatekeyots;

    /**
     * the winternitz parameter
     */
    private int w;

    /**
     * the source of randomness for ots private key generation
     */
    private gmssrandom gmssrandom;

    /**
     * sizes of the message and the checksum, both
     */
    private int messagesize, checksumsize;

    /**
     * the constructor generates an ots key pair, using <code>seed0</code> and
     * the prng
     * <p/>
     *
     * @param seed0    the seed for the prgn
     * @param digest an array of strings, containing the name of the used hash
     *                 function, the name of the prgn and the names of the
     *                 corresponding providers
     * @param w        the winternitz parameter
     */
    public winternitzotsignature(byte[] seed0, digest digest, int w)
    {
        // this.name = name;
        this.w = w;

        messdigestots = digest;

        gmssrandom = new gmssrandom(messdigestots);

        // calulate keysize for private and public key and also the help
        // array

        mdsize = messdigestots.getdigestsize();
        int mdsizebit = mdsize << 3;
        messagesize = (int)math.ceil((double)(mdsizebit) / (double)w);

        checksumsize = getlog((messagesize << w) + 1);

        keysize = messagesize
            + (int)math.ceil((double)checksumsize / (double)w);

        /*
           * mdsize = messdigestots.getdigestlength(); messagesize =
           * ((mdsize<<3)+(w-1))/w;
           *
           * checksumsize = getlog((messagesize<<w)+1);
           *
           * keysize = messagesize + (checksumsize+w-1)/w;
           */
        // define the private key messagesize
        privatekeyots = new byte[keysize][mdsize];

        // gmssrandom.setseed(seed0);
        byte[] dummy = new byte[mdsize];
        system.arraycopy(seed0, 0, dummy, 0, dummy.length);

        // generate random bytes and
        // assign them to the private key
        for (int i = 0; i < keysize; i++)
        {
            privatekeyots[i] = gmssrandom.nextseed(dummy);
        }
    }

    /**
     * @return the private ots key
     */
    public byte[][] getprivatekey()
    {
        return privatekeyots;
    }

    /**
     * @return the public ots key
     */
    public byte[] getpublickey()
    {
        byte[] helppubkey = new byte[keysize * mdsize];

        byte[] help = new byte[mdsize];
        int two_power_t = 1 << w;

        for (int i = 0; i < keysize; i++)
        {
            // hash w-1 time the private key and assign it to the public key
            messdigestots.update(privatekeyots[i], 0, privatekeyots[i].length);
            help = new byte[messdigestots.getdigestsize()];
            messdigestots.dofinal(help, 0);
            for (int j = 2; j < two_power_t; j++)
            {
                messdigestots.update(help, 0, help.length);
                help = new byte[messdigestots.getdigestsize()];
                messdigestots.dofinal(help, 0);
            }
            system.arraycopy(help, 0, helppubkey, mdsize * i, mdsize);
        }

        messdigestots.update(helppubkey, 0, helppubkey.length);
        byte[] tmp = new byte[messdigestots.getdigestsize()];
        messdigestots.dofinal(tmp, 0);
        return tmp;
    }

    /**
     * @return the one-time signature of the message, generated with the private
     *         key
     */
    public byte[] getsignature(byte[] message)
    {
        byte[] sign = new byte[keysize * mdsize];
        // byte [] message; // message m as input
        byte[] hash = new byte[mdsize]; // hash of message m
        int counter = 0;
        int c = 0;
        int test = 0;
        // create hash of message m
        messdigestots.update(message, 0, message.length);
        hash = new byte[messdigestots.getdigestsize()];
        messdigestots.dofinal(hash, 0);

        if (8 % w == 0)
        {
            int d = 8 / w;
            int k = (1 << w) - 1;
            byte[] hlp = new byte[mdsize];

            // create signature
            for (int i = 0; i < hash.length; i++)
            {
                for (int j = 0; j < d; j++)
                {
                    test = hash[i] & k;
                    c += test;

                    system.arraycopy(privatekeyots[counter], 0, hlp, 0, mdsize);

                    while (test > 0)
                    {
                        messdigestots.update(hlp, 0, hlp.length);
                        hlp = new byte[messdigestots.getdigestsize()];
                        messdigestots.dofinal(hlp, 0);
                        test--;
                    }
                    system.arraycopy(hlp, 0, sign, counter * mdsize, mdsize);
                    hash[i] = (byte)(hash[i] >>> w);
                    counter++;
                }
            }

            c = (messagesize << w) - c;
            for (int i = 0; i < checksumsize; i += w)
            {
                test = c & k;

                system.arraycopy(privatekeyots[counter], 0, hlp, 0, mdsize);

                while (test > 0)
                {
                    messdigestots.update(hlp, 0, hlp.length);
                    hlp = new byte[messdigestots.getdigestsize()];
                    messdigestots.dofinal(hlp, 0);
                    test--;
                }
                system.arraycopy(hlp, 0, sign, counter * mdsize, mdsize);
                c >>>= w;
                counter++;
            }
        }
        else if (w < 8)
        {
            int d = mdsize / w;
            int k = (1 << w) - 1;
            byte[] hlp = new byte[mdsize];
            long big8;
            int ii = 0;
            // create signature
            // first d*w bytes of hash
            for (int i = 0; i < d; i++)
            {
                big8 = 0;
                for (int j = 0; j < w; j++)
                {
                    big8 ^= (hash[ii] & 0xff) << (j << 3);
                    ii++;
                }
                for (int j = 0; j < 8; j++)
                {
                    test = (int)(big8 & k);
                    c += test;

                    system.arraycopy(privatekeyots[counter], 0, hlp, 0, mdsize);

                    while (test > 0)
                    {
                        messdigestots.update(hlp, 0, hlp.length);
                        hlp = new byte[messdigestots.getdigestsize()];
                        messdigestots.dofinal(hlp, 0);
                        test--;
                    }
                    system.arraycopy(hlp, 0, sign, counter * mdsize, mdsize);
                    big8 >>>= w;
                    counter++;
                }
            }
            // rest of hash
            d = mdsize % w;
            big8 = 0;
            for (int j = 0; j < d; j++)
            {
                big8 ^= (hash[ii] & 0xff) << (j << 3);
                ii++;
            }
            d <<= 3;
            for (int j = 0; j < d; j += w)
            {
                test = (int)(big8 & k);
                c += test;

                system.arraycopy(privatekeyots[counter], 0, hlp, 0, mdsize);

                while (test > 0)
                {
                    messdigestots.update(hlp, 0, hlp.length);
                    hlp = new byte[messdigestots.getdigestsize()];
                    messdigestots.dofinal(hlp, 0);
                    test--;
                }
                system.arraycopy(hlp, 0, sign, counter * mdsize, mdsize);
                big8 >>>= w;
                counter++;
            }

            // check bytes
            c = (messagesize << w) - c;
            for (int i = 0; i < checksumsize; i += w)
            {
                test = c & k;

                system.arraycopy(privatekeyots[counter], 0, hlp, 0, mdsize);

                while (test > 0)
                {
                    messdigestots.update(hlp, 0, hlp.length);
                    hlp = new byte[messdigestots.getdigestsize()];
                    messdigestots.dofinal(hlp, 0);
                    test--;
                }
                system.arraycopy(hlp, 0, sign, counter * mdsize, mdsize);
                c >>>= w;
                counter++;
            }
        }// end if(w<8)
        else if (w < 57)
        {
            int d = (mdsize << 3) - w;
            int k = (1 << w) - 1;
            byte[] hlp = new byte[mdsize];
            long big8, test8;
            int r = 0;
            int s, f, rest, ii;
            // create signature
            // first a*w bits of hash where a*w <= 8*mdsize < (a+1)*w
            while (r <= d)
            {
                s = r >>> 3;
                rest = r % 8;
                r += w;
                f = (r + 7) >>> 3;
                big8 = 0;
                ii = 0;
                for (int j = s; j < f; j++)
                {
                    big8 ^= (hash[j] & 0xff) << (ii << 3);
                    ii++;
                }

                big8 >>>= rest;
                test8 = (big8 & k);
                c += test8;

                system.arraycopy(privatekeyots[counter], 0, hlp, 0, mdsize);
                while (test8 > 0)
                {
                    messdigestots.update(hlp, 0, hlp.length);
                    hlp = new byte[messdigestots.getdigestsize()];
                    messdigestots.dofinal(hlp, 0);
                    test8--;
                }
                system.arraycopy(hlp, 0, sign, counter * mdsize, mdsize);
                counter++;

            }
            // rest of hash
            s = r >>> 3;
            if (s < mdsize)
            {
                rest = r % 8;
                big8 = 0;
                ii = 0;
                for (int j = s; j < mdsize; j++)
                {
                    big8 ^= (hash[j] & 0xff) << (ii << 3);
                    ii++;
                }

                big8 >>>= rest;
                test8 = (big8 & k);
                c += test8;

                system.arraycopy(privatekeyots[counter], 0, hlp, 0, mdsize);
                while (test8 > 0)
                {
                    messdigestots.update(hlp, 0, hlp.length);
                    hlp = new byte[messdigestots.getdigestsize()];
                    messdigestots.dofinal(hlp, 0);
                    test8--;
                }
                system.arraycopy(hlp, 0, sign, counter * mdsize, mdsize);
                counter++;
            }
            // check bytes
            c = (messagesize << w) - c;
            for (int i = 0; i < checksumsize; i += w)
            {
                test8 = (c & k);

                system.arraycopy(privatekeyots[counter], 0, hlp, 0, mdsize);

                while (test8 > 0)
                {
                    messdigestots.update(hlp, 0, hlp.length);
                    hlp = new byte[messdigestots.getdigestsize()];
                    messdigestots.dofinal(hlp, 0);
                    test8--;
                }
                system.arraycopy(hlp, 0, sign, counter * mdsize, mdsize);
                c >>>= w;
                counter++;
            }
        }// end if(w<57)

        return sign;
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

}
