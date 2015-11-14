package org.ripple.bouncycastle.pqc.crypto.gmss.util;

import org.ripple.bouncycastle.crypto.digest;

/**
 * this class implements signature verification of the winternitz one-time
 * signature scheme (otss), described in c.dods, n.p. smart, and m. stam, "hash
 * based digital signature schemes", lncs 3796, pages 96&#8211;115, 2005. the
 * class is used by the gmss classes.
 */
public class winternitzotsverify
{

    private digest messdigestots;

    /**
     * the winternitz parameter
     */
    private int w;

    /**
     * the constructor
     * <p/>
     *
     * @param digest the name of the hash function used by the ots and the provider
     *               name of the hash function
     * @param w      the winternitz parameter
     */
    public winternitzotsverify(digest digest, int w)
    {
        this.w = w;

        messdigestots = digest;
    }

    /**
     * @return the length of the one-time signature
     */
    public int getsignaturelength()
    {
        int mdsize = messdigestots.getdigestsize();
        int size = ((mdsize << 3) + (w - 1)) / w;
        int logs = getlog((size << w) + 1);
        size += (logs + w - 1) / w;

        return mdsize * size;
    }

    /**
     * this method computes the public ots key from the one-time signature of a
     * message. this is *not* a complete ots signature verification, but it
     * suffices for usage with cmss.
     *
     * @param message   the message
     * @param signature the one-time signature
     * @return the public ots key
     */
    public byte[] verify(byte[] message, byte[] signature)
    {

        int mdsize = messdigestots.getdigestsize();
        byte[] hash = new byte[mdsize]; // hash of message m

        // create hash of message m
        messdigestots.update(message, 0, message.length);
        hash = new byte[messdigestots.getdigestsize()];
        messdigestots.dofinal(hash, 0);

        int size = ((mdsize << 3) + (w - 1)) / w;
        int logs = getlog((size << w) + 1);
        int keysize = size + (logs + w - 1) / w;

        int testkeysize = mdsize * keysize;

        if (testkeysize != signature.length)
        {
            return null;
        }

        byte[] testkey = new byte[testkeysize];

        int c = 0;
        int counter = 0;
        int test;

        if (8 % w == 0)
        {
            int d = 8 / w;
            int k = (1 << w) - 1;
            byte[] hlp = new byte[mdsize];

            // verify signature
            for (int i = 0; i < hash.length; i++)
            {
                for (int j = 0; j < d; j++)
                {
                    test = hash[i] & k;
                    c += test;

                    system.arraycopy(signature, counter * mdsize, hlp, 0, mdsize);

                    while (test < k)
                    {
                        messdigestots.update(hlp, 0, hlp.length);
                        hlp = new byte[messdigestots.getdigestsize()];
                        messdigestots.dofinal(hlp, 0);
                        test++;
                    }

                    system.arraycopy(hlp, 0, testkey, counter * mdsize, mdsize);
                    hash[i] = (byte)(hash[i] >>> w);
                    counter++;
                }
            }

            c = (size << w) - c;
            for (int i = 0; i < logs; i += w)
            {
                test = c & k;

                system.arraycopy(signature, counter * mdsize, hlp, 0, mdsize);

                while (test < k)
                {
                    messdigestots.update(hlp, 0, hlp.length);
                    hlp = new byte[messdigestots.getdigestsize()];
                    messdigestots.dofinal(hlp, 0);
                    test++;
                }
                system.arraycopy(hlp, 0, testkey, counter * mdsize, mdsize);
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

                    system.arraycopy(signature, counter * mdsize, hlp, 0, mdsize);

                    while (test < k)
                    {
                        messdigestots.update(hlp, 0, hlp.length);
                        hlp = new byte[messdigestots.getdigestsize()];
                        messdigestots.dofinal(hlp, 0);
                        test++;
                    }

                    system.arraycopy(hlp, 0, testkey, counter * mdsize, mdsize);
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

                system.arraycopy(signature, counter * mdsize, hlp, 0, mdsize);

                while (test < k)
                {
                    messdigestots.update(hlp, 0, hlp.length);
                    hlp = new byte[messdigestots.getdigestsize()];
                    messdigestots.dofinal(hlp, 0);
                    test++;
                }

                system.arraycopy(hlp, 0, testkey, counter * mdsize, mdsize);
                big8 >>>= w;
                counter++;
            }

            // check bytes
            c = (size << w) - c;
            for (int i = 0; i < logs; i += w)
            {
                test = c & k;

                system.arraycopy(signature, counter * mdsize, hlp, 0, mdsize);

                while (test < k)
                {
                    messdigestots.update(hlp, 0, hlp.length);
                    hlp = new byte[messdigestots.getdigestsize()];
                    messdigestots.dofinal(hlp, 0);
                    test++;
                }

                system.arraycopy(hlp, 0, testkey, counter * mdsize, mdsize);
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

                system.arraycopy(signature, counter * mdsize, hlp, 0, mdsize);

                while (test8 < k)
                {
                    messdigestots.update(hlp, 0, hlp.length);
                    hlp = new byte[messdigestots.getdigestsize()];
                    messdigestots.dofinal(hlp, 0);
                    test8++;
                }

                system.arraycopy(hlp, 0, testkey, counter * mdsize, mdsize);
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

                system.arraycopy(signature, counter * mdsize, hlp, 0, mdsize);

                while (test8 < k)
                {
                    messdigestots.update(hlp, 0, hlp.length);
                    hlp = new byte[messdigestots.getdigestsize()];
                    messdigestots.dofinal(hlp, 0);
                    test8++;
                }

                system.arraycopy(hlp, 0, testkey, counter * mdsize, mdsize);
                counter++;
            }
            // check bytes
            c = (size << w) - c;
            for (int i = 0; i < logs; i += w)
            {
                test8 = (c & k);

                system.arraycopy(signature, counter * mdsize, hlp, 0, mdsize);

                while (test8 < k)
                {
                    messdigestots.update(hlp, 0, hlp.length);
                    hlp = new byte[messdigestots.getdigestsize()];
                    messdigestots.dofinal(hlp, 0);
                    test8++;
                }

                system.arraycopy(hlp, 0, testkey, counter * mdsize, mdsize);
                c >>>= w;
                counter++;
            }
        }// end if(w<57)

        byte[] tkey = new byte[mdsize];
        messdigestots.update(testkey, 0, testkey.length);
        tkey = new byte[messdigestots.getdigestsize()];
        messdigestots.dofinal(tkey, 0);

        return tkey;

    }

    /**
     * this method returns the least integer that is greater or equal to the
     * logarithm to the base 2 of an integer <code>intvalue</code>.
     *
     * @param intvalue an integer
     * @return the least integer greater or equal to the logarithm to the base
     *         256 of <code>intvalue</code>
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
