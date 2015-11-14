/*
 * licensed to the apache software foundation (asf) under one or more
 * contributor license agreements. see the notice file distributed with
 * this work for additional information regarding copyright ownership.
 * the asf licenses this file to you under the apache license, version 2.0
 * (the "license"); you may not use this file except in compliance with
 * the license. you may obtain a copy of the license at
 *
 * http://www.apache.org/licenses/license-2.0
 *
 * unless required by applicable law or agreed to in writing, software
 * distributed under the license is distributed on an "as is" basis,
 * without warranties or conditions of any kind, either express or implied.
 * see the license for the specific language governing permissions and
 * limitations under the license.
 *
 */

/*
 * this package is based on the work done by keiron liddle, aftex software
 * <keiron@aftexsw.com> to whom the ant project is very grateful for his
 * great code.
 */
package org.ripple.bouncycastle.apache.bzip2;

import java.io.inputstream;
import java.io.ioexception;

/**
 * an input stream that decompresses from the bzip2 format (with the file
 * header chars) to be read as any other stream.
 *
 * @author <a href="mailto:keiron@aftexsw.com">keiron liddle</a>
 *
 * <b>nb:</b> note this class has been modified to read the leading bz from the
 * start of the bzip2 stream to make it compatible with other pgp programs.
 */
public class cbzip2inputstream extends inputstream implements bzip2constants {
    private static void cadvise() {
        system.out.println("crc error");
        //throw new ccoruptionerror();
    }

//    private static void badbglengths() {
//        cadvise();
//    }
//
//    private static void bitstreameof() {
//        cadvise();
//    }

    private static void compressedstreameof() {
        cadvise();
    }

    private void makemaps() {
        int i;
        ninuse = 0;
        for (i = 0; i < 256; i++) {
            if (inuse[i]) {
                seqtounseq[ninuse] = (char) i;
                unseqtoseq[i] = (char) ninuse;
                ninuse++;
            }
        }
    }

    /*
      index of the last char in the block, so
      the block size == last + 1.
    */
    private int  last;

    /*
      index in zptr[] of original string after sorting.
    */
    private int  origptr;

    /*
      always: in the range 0 .. 9.
      the current block size is 100000 * this number.
    */
    private int blocksize100k;

    private boolean blockrandomised;

    private int bsbuff;
    private int bslive;
    private crc mcrc = new crc();

    private boolean[] inuse = new boolean[256];
    private int ninuse;

    private char[] seqtounseq = new char[256];
    private char[] unseqtoseq = new char[256];

    private char[] selector = new char[max_selectors];
    private char[] selectormtf = new char[max_selectors];

    private int[] tt;
    private char[] ll8;

    /*
      freq table collected to save a pass over the data
      during decompression.
    */
    private int[] unzftab = new int[256];

    private int[][] limit = new int[n_groups][max_alpha_size];
    private int[][] base = new int[n_groups][max_alpha_size];
    private int[][] perm = new int[n_groups][max_alpha_size];
    private int[] minlens = new int[n_groups];

    private inputstream bsstream;

    private boolean streamend = false;

    private int currentchar = -1;

    private static final int start_block_state = 1;
    private static final int rand_part_a_state = 2;
    private static final int rand_part_b_state = 3;
    private static final int rand_part_c_state = 4;
    private static final int no_rand_part_a_state = 5;
    private static final int no_rand_part_b_state = 6;
    private static final int no_rand_part_c_state = 7;

    private int currentstate = start_block_state;

    private int storedblockcrc, storedcombinedcrc;
    private int computedblockcrc, computedcombinedcrc;

    int i2, count, chprev, ch2;
    int i, tpos;
    int rntogo = 0;
    int rtpos  = 0;
    int j2;
    char z;

    public cbzip2inputstream(inputstream zstream)
        throws ioexception
    {
        ll8 = null;
        tt = null;
        bssetstream(zstream);
        initialize();
        initblock();
        setupblock();
    }

    public int read() {
        if (streamend) {
            return -1;
        } else {
            int retchar = currentchar;
            switch(currentstate) {
            case start_block_state:
                break;
            case rand_part_a_state:
                break;
            case rand_part_b_state:
                setuprandpartb();
                break;
            case rand_part_c_state:
                setuprandpartc();
                break;
            case no_rand_part_a_state:
                break;
            case no_rand_part_b_state:
                setupnorandpartb();
                break;
            case no_rand_part_c_state:
                setupnorandpartc();
                break;
            default:
                break;
            }
            return retchar;
        }
    }

    private void initialize() throws ioexception {
        char magic3, magic4;
        magic3 = bsgetuchar();
        magic4 = bsgetuchar();
        if (magic3 != 'b' && magic4 != 'z')
        {
            throw new ioexception("not a bzip2 marked stream");
        }
        magic3 = bsgetuchar();
        magic4 = bsgetuchar();
        if (magic3 != 'h' || magic4 < '1' || magic4 > '9') {
            bsfinishedwithstream();
            streamend = true;
            return;
        }

        setdecompressstructuresizes(magic4 - '0');
        computedcombinedcrc = 0;
    }

    private void initblock() {
        char magic1, magic2, magic3, magic4;
        char magic5, magic6;
        magic1 = bsgetuchar();
        magic2 = bsgetuchar();
        magic3 = bsgetuchar();
        magic4 = bsgetuchar();
        magic5 = bsgetuchar();
        magic6 = bsgetuchar();
        if (magic1 == 0x17 && magic2 == 0x72 && magic3 == 0x45
            && magic4 == 0x38 && magic5 == 0x50 && magic6 == 0x90) {
            complete();
            return;
        }

        if (magic1 != 0x31 || magic2 != 0x41 || magic3 != 0x59
            || magic4 != 0x26 || magic5 != 0x53 || magic6 != 0x59) {
            badblockheader();
            streamend = true;
            return;
        }

        storedblockcrc = bsgetint32();

        if (bsr(1) == 1) {
            blockrandomised = true;
        } else {
            blockrandomised = false;
        }

        //        currblockno++;
        getandmovetofrontdecode();

        mcrc.initialisecrc();
        currentstate = start_block_state;
    }

    private void endblock() {
        computedblockcrc = mcrc.getfinalcrc();
        /* a bad crc is considered a fatal error. */
        if (storedblockcrc != computedblockcrc) {
            crcerror();
        }

        computedcombinedcrc = (computedcombinedcrc << 1)
            | (computedcombinedcrc >>> 31);
        computedcombinedcrc ^= computedblockcrc;
    }

    private void complete() {
        storedcombinedcrc = bsgetint32();
        if (storedcombinedcrc != computedcombinedcrc) {
            crcerror();
        }

        bsfinishedwithstream();
        streamend = true;
    }

    private static void blockoverrun() {
        cadvise();
    }

    private static void badblockheader() {
        cadvise();
    }

    private static void crcerror() {
        cadvise();
    }

    private void bsfinishedwithstream() {
        try {
            if (this.bsstream != null) {
                if (this.bsstream != system.in) {
                    this.bsstream.close();
                    this.bsstream = null;
                }
            }
        } catch (ioexception ioe) {
            //ignore
        }
    }

    private void bssetstream(inputstream f) {
        bsstream = f;
        bslive = 0;
        bsbuff = 0;
    }

    private int bsr(int n) {
        int v;
        while (bslive < n) {
            int zzi;
            char thech = 0;
            try {
                thech = (char) bsstream.read();
            } catch (ioexception e) {
                compressedstreameof();
            }
            if (thech == -1) {
                compressedstreameof();
            }
            zzi = thech;
            bsbuff = (bsbuff << 8) | (zzi & 0xff);
            bslive += 8;
        }

        v = (bsbuff >> (bslive - n)) & ((1 << n) - 1);
        bslive -= n;
        return v;
    }

    private char bsgetuchar() {
        return (char) bsr(8);
    }

    private int bsgetint() {
        int u = 0;
        u = (u << 8) | bsr(8);
        u = (u << 8) | bsr(8);
        u = (u << 8) | bsr(8);
        u = (u << 8) | bsr(8);
        return u;
    }

    private int bsgetintvs(int numbits) {
        return (int) bsr(numbits);
    }

    private int bsgetint32() {
        return (int) bsgetint();
    }

    private void hbcreatedecodetables(int[] limit, int[] base,
                                      int[] perm, char[] length,
                                      int minlen, int maxlen, int alphasize) {
        int pp, i, j, vec;

        pp = 0;
        for (i = minlen; i <= maxlen; i++) {
            for (j = 0; j < alphasize; j++) {
                if (length[j] == i) {
                    perm[pp] = j;
                    pp++;
                }
            }
        }

        for (i = 0; i < max_code_len; i++) {
            base[i] = 0;
        }
        for (i = 0; i < alphasize; i++) {
            base[length[i] + 1]++;
        }

        for (i = 1; i < max_code_len; i++) {
            base[i] += base[i - 1];
        }

        for (i = 0; i < max_code_len; i++) {
            limit[i] = 0;
        }
        vec = 0;

        for (i = minlen; i <= maxlen; i++) {
            vec += (base[i + 1] - base[i]);
            limit[i] = vec - 1;
            vec <<= 1;
        }
        for (i = minlen + 1; i <= maxlen; i++) {
            base[i] = ((limit[i - 1] + 1) << 1) - base[i];
        }
    }

    private void recvdecodingtables() {
        char len[][] = new char[n_groups][max_alpha_size];
        int i, j, t, ngroups, nselectors, alphasize;
        int minlen, maxlen;
        boolean[] inuse16 = new boolean[16];

        /* receive the mapping table */
        for (i = 0; i < 16; i++) {
            if (bsr(1) == 1) {
                inuse16[i] = true;
            } else {
                inuse16[i] = false;
            }
        }

        for (i = 0; i < 256; i++) {
            inuse[i] = false;
        }

        for (i = 0; i < 16; i++) {
            if (inuse16[i]) {
                for (j = 0; j < 16; j++) {
                    if (bsr(1) == 1) {
                        inuse[i * 16 + j] = true;
                    }
                }
            }
        }

        makemaps();
        alphasize = ninuse + 2;

        /* now the selectors */
        ngroups = bsr(3);
        nselectors = bsr(15);
        for (i = 0; i < nselectors; i++) {
            j = 0;
            while (bsr(1) == 1) {
                j++;
            }
            selectormtf[i] = (char) j;
        }

        /* undo the mtf values for the selectors. */
        {
            char[] pos = new char[n_groups];
            char tmp, v;
            for (v = 0; v < ngroups; v++) {
                pos[v] = v;
            }

            for (i = 0; i < nselectors; i++) {
                v = selectormtf[i];
                tmp = pos[v];
                while (v > 0) {
                    pos[v] = pos[v - 1];
                    v--;
                }
                pos[0] = tmp;
                selector[i] = tmp;
            }
        }

        /* now the coding tables */
        for (t = 0; t < ngroups; t++) {
            int curr = bsr(5);
            for (i = 0; i < alphasize; i++) {
                while (bsr(1) == 1) {
                    if (bsr(1) == 0) {
                        curr++;
                    } else {
                        curr--;
                    }
                }
                len[t][i] = (char) curr;
            }
        }

        /* create the huffman decoding tables */
        for (t = 0; t < ngroups; t++) {
            minlen = 32;
            maxlen = 0;
            for (i = 0; i < alphasize; i++) {
                if (len[t][i] > maxlen) {
                    maxlen = len[t][i];
                }
                if (len[t][i] < minlen) {
                    minlen = len[t][i];
                }
            }
            hbcreatedecodetables(limit[t], base[t], perm[t], len[t], minlen,
                                 maxlen, alphasize);
            minlens[t] = minlen;
        }
    }

    private void getandmovetofrontdecode() {
        char[] yy = new char[256];
        int i, j, nextsym, limitlast;
        int eob, groupno, grouppos;

        limitlast = baseblocksize * blocksize100k;
        origptr = bsgetintvs(24);

        recvdecodingtables();
        eob = ninuse + 1;
        groupno = -1;
        grouppos = 0;

        /*
          setting up the unzftab entries here is not strictly
          necessary, but it does save having to do it later
          in a separate pass, and so saves a block's worth of
          cache misses.
        */
        for (i = 0; i <= 255; i++) {
            unzftab[i] = 0;
        }

        for (i = 0; i <= 255; i++) {
            yy[i] = (char) i;
        }

        last = -1;

        {
            int zt, zn, zvec, zj;
            if (grouppos == 0) {
                groupno++;
                grouppos = g_size;
            }
            grouppos--;
            zt = selector[groupno];
            zn = minlens[zt];
            zvec = bsr(zn);
            while (zvec > limit[zt][zn]) {
                zn++;
                {
                    {
                        while (bslive < 1) {
                            int zzi;
                            char thech = 0;
                            try {
                                thech = (char) bsstream.read();
                            } catch (ioexception e) {
                                compressedstreameof();
                            }
                            if (thech == -1) {
                                compressedstreameof();
                            }
                            zzi = thech;
                            bsbuff = (bsbuff << 8) | (zzi & 0xff);
                            bslive += 8;
                        }
                    }
                    zj = (bsbuff >> (bslive - 1)) & 1;
                    bslive--;
                }
                zvec = (zvec << 1) | zj;
            }
            nextsym = perm[zt][zvec - base[zt][zn]];
        }

        while (true) {

            if (nextsym == eob) {
                break;
            }

            if (nextsym == runa || nextsym == runb) {
                char ch;
                int s = -1;
                int n = 1;
                do {
                    if (nextsym == runa) {
                        s = s + (0 + 1) * n;
                    } else if (nextsym == runb) {
                        s = s + (1 + 1) * n;
                           }
                    n = n * 2;
                    {
                        int zt, zn, zvec, zj;
                        if (grouppos == 0) {
                            groupno++;
                            grouppos = g_size;
                        }
                        grouppos--;
                        zt = selector[groupno];
                        zn = minlens[zt];
                        zvec = bsr(zn);
                        while (zvec > limit[zt][zn]) {
                            zn++;
                            {
                                {
                                    while (bslive < 1) {
                                        int zzi;
                                        char thech = 0;
                                        try {
                                            thech = (char) bsstream.read();
                                        } catch (ioexception e) {
                                            compressedstreameof();
                                        }
                                        if (thech == -1) {
                                            compressedstreameof();
                                        }
                                        zzi = thech;
                                        bsbuff = (bsbuff << 8) | (zzi & 0xff);
                                        bslive += 8;
                                    }
                                }
                                zj = (bsbuff >> (bslive - 1)) & 1;
                                bslive--;
                            }
                            zvec = (zvec << 1) | zj;
                        }
                        nextsym = perm[zt][zvec - base[zt][zn]];
                    }
                } while (nextsym == runa || nextsym == runb);

                s++;
                ch = seqtounseq[yy[0]];
                unzftab[ch] += s;

                while (s > 0) {
                    last++;
                    ll8[last] = ch;
                    s--;
                }

                if (last >= limitlast) {
                    blockoverrun();
                }
                continue;
            } else {
                char tmp;
                last++;
                if (last >= limitlast) {
                    blockoverrun();
                }

                tmp = yy[nextsym - 1];
                unzftab[seqtounseq[tmp]]++;
                ll8[last] = seqtounseq[tmp];

                /*
                  this loop is hammered during decompression,
                  hence the unrolling.

                  for (j = nextsym-1; j > 0; j--) yy[j] = yy[j-1];
                */

                j = nextsym - 1;
                for (; j > 3; j -= 4) {
                    yy[j]     = yy[j - 1];
                    yy[j - 1] = yy[j - 2];
                    yy[j - 2] = yy[j - 3];
                    yy[j - 3] = yy[j - 4];
                }
                for (; j > 0; j--) {
                    yy[j] = yy[j - 1];
                }

                yy[0] = tmp;
                {
                    int zt, zn, zvec, zj;
                    if (grouppos == 0) {
                        groupno++;
                        grouppos = g_size;
                    }
                    grouppos--;
                    zt = selector[groupno];
                    zn = minlens[zt];
                    zvec = bsr(zn);
                    while (zvec > limit[zt][zn]) {
                        zn++;
                        {
                            {
                                while (bslive < 1) {
                                    int zzi;
                                    char thech = 0;
                                    try {
                                        thech = (char) bsstream.read();
                                    } catch (ioexception e) {
                                        compressedstreameof();
                                    }
                                    zzi = thech;
                                    bsbuff = (bsbuff << 8) | (zzi & 0xff);
                                    bslive += 8;
                                }
                            }
                            zj = (bsbuff >> (bslive - 1)) & 1;
                            bslive--;
                        }
                        zvec = (zvec << 1) | zj;
                    }
                    nextsym = perm[zt][zvec - base[zt][zn]];
                }
                continue;
            }
        }
    }

    private void setupblock() {
        int[] cftab = new int[257];
        char ch;

        cftab[0] = 0;
        for (i = 1; i <= 256; i++) {
            cftab[i] = unzftab[i - 1];
        }
        for (i = 1; i <= 256; i++) {
            cftab[i] += cftab[i - 1];
        }

        for (i = 0; i <= last; i++) {
            ch = (char) ll8[i];
            tt[cftab[ch]] = i;
            cftab[ch]++;
        }
        cftab = null;

        tpos = tt[origptr];

        count = 0;
        i2 = 0;
        ch2 = 256;   /* not a char and not eof */

        if (blockrandomised) {
            rntogo = 0;
            rtpos = 0;
            setuprandparta();
        } else {
            setupnorandparta();
        }
    }

    private void setuprandparta() {
        if (i2 <= last) {
            chprev = ch2;
            ch2 = ll8[tpos];
            tpos = tt[tpos];
            if (rntogo == 0) {
                rntogo = rnums[rtpos];
                rtpos++;
                if (rtpos == 512) {
                    rtpos = 0;
                }
            }
            rntogo--;
            ch2 ^= (int) ((rntogo == 1) ? 1 : 0);
            i2++;

            currentchar = ch2;
            currentstate = rand_part_b_state;
            mcrc.updatecrc(ch2);
        } else {
            endblock();
            initblock();
            setupblock();
        }
    }

    private void setupnorandparta() {
        if (i2 <= last) {
            chprev = ch2;
            ch2 = ll8[tpos];
            tpos = tt[tpos];
            i2++;

            currentchar = ch2;
            currentstate = no_rand_part_b_state;
            mcrc.updatecrc(ch2);
        } else {
            endblock();
            initblock();
            setupblock();
        }
    }

    private void setuprandpartb() {
        if (ch2 != chprev) {
            currentstate = rand_part_a_state;
            count = 1;
            setuprandparta();
        } else {
            count++;
            if (count >= 4) {
                z = ll8[tpos];
                tpos = tt[tpos];
                if (rntogo == 0) {
                    rntogo = rnums[rtpos];
                    rtpos++;
                    if (rtpos == 512) {
                        rtpos = 0;
                    }
                }
                rntogo--;
                z ^= ((rntogo == 1) ? 1 : 0);
                j2 = 0;
                currentstate = rand_part_c_state;
                setuprandpartc();
            } else {
                currentstate = rand_part_a_state;
                setuprandparta();
            }
        }
    }

    private void setuprandpartc() {
        if (j2 < (int) z) {
            currentchar = ch2;
            mcrc.updatecrc(ch2);
            j2++;
        } else {
            currentstate = rand_part_a_state;
            i2++;
            count = 0;
            setuprandparta();
        }
    }

    private void setupnorandpartb() {
        if (ch2 != chprev) {
            currentstate = no_rand_part_a_state;
            count = 1;
            setupnorandparta();
        } else {
            count++;
            if (count >= 4) {
                z = ll8[tpos];
                tpos = tt[tpos];
                currentstate = no_rand_part_c_state;
                j2 = 0;
                setupnorandpartc();
            } else {
                currentstate = no_rand_part_a_state;
                setupnorandparta();
            }
        }
    }

    private void setupnorandpartc() {
        if (j2 < (int) z) {
            currentchar = ch2;
            mcrc.updatecrc(ch2);
            j2++;
        } else {
            currentstate = no_rand_part_a_state;
            i2++;
            count = 0;
            setupnorandparta();
        }
    }

    private void setdecompressstructuresizes(int newsize100k) {
        if (!(0 <= newsize100k && newsize100k <= 9 && 0 <= blocksize100k
               && blocksize100k <= 9)) {
            // throw new ioexception("invalid block size");
        }

        blocksize100k = newsize100k;

        if (newsize100k == 0) {
            return;
        }

        int n = baseblocksize * newsize100k;
        ll8 = new char[n];
        tt = new int[n];
    }
}

