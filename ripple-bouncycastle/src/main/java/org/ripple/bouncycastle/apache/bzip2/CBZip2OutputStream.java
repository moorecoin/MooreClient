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

import java.io.outputstream;
import java.io.ioexception;

/**
 * an output stream that compresses into the bzip2 format (with the file
 * header chars) into another stream.
 *
 * @author <a href="mailto:keiron@aftexsw.com">keiron liddle</a>
 *
 * todo:    update to bzip2 1.0.1
 * <b>nb:</b> note this class has been modified to add a leading bz to the
 * start of the bzip2 stream to make it compatible with other pgp programs.
 */
public class cbzip2outputstream extends outputstream implements bzip2constants {
    protected static final int setmask = (1 << 21);
    protected static final int clearmask = (~setmask);
    protected static final int greater_icost = 15;
    protected static final int lesser_icost = 0;
    protected static final int small_thresh = 20;
    protected static final int depth_thresh = 10;

    /*
      if you are ever unlucky/improbable enough
      to get a stack overflow whilst sorting,
      increase the following constant and try
      again.  in practice i have never seen the
      stack go above 27 elems, so the following
      limit seems very generous.
    */
    protected static final int qsort_stack_size = 1000;
    private boolean finished;

    private static void panic() {
        system.out.println("panic");
        //throw new cerror();
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

    protected static void hbmakecodelengths(char[] len, int[] freq,
                                            int alphasize, int maxlen) {
        /*
          nodes and heap entries run from 1.  entry 0
          for both the heap and nodes is a sentinel.
        */
        int nnodes, nheap, n1, n2, i, j, k;
        boolean  toolong;

        int[] heap = new int[max_alpha_size + 2];
        int[] weight = new int[max_alpha_size * 2];
        int[] parent = new int[max_alpha_size * 2];

        for (i = 0; i < alphasize; i++) {
            weight[i + 1] = (freq[i] == 0 ? 1 : freq[i]) << 8;
        }

        while (true) {
            nnodes = alphasize;
            nheap = 0;

            heap[0] = 0;
            weight[0] = 0;
            parent[0] = -2;

            for (i = 1; i <= alphasize; i++) {
                parent[i] = -1;
                nheap++;
                heap[nheap] = i;
                {
                    int zz, tmp;
                    zz = nheap;
                    tmp = heap[zz];
                    while (weight[tmp] < weight[heap[zz >> 1]]) {
                        heap[zz] = heap[zz >> 1];
                        zz >>= 1;
                    }
                    heap[zz] = tmp;
                }
            }
            if (!(nheap < (max_alpha_size + 2))) {
                panic();
            }

            while (nheap > 1) {
                n1 = heap[1];
                heap[1] = heap[nheap];
                nheap--;
                {
                    int zz = 0, yy = 0, tmp = 0;
                    zz = 1;
                    tmp = heap[zz];
                    while (true) {
                        yy = zz << 1;
                        if (yy > nheap) {
                            break;
                        }
                        if (yy < nheap
                            && weight[heap[yy + 1]] < weight[heap[yy]]) {
                            yy++;
                        }
                        if (weight[tmp] < weight[heap[yy]]) {
                            break;
                        }
                        heap[zz] = heap[yy];
                        zz = yy;
                    }
                    heap[zz] = tmp;
                }
                n2 = heap[1];
                heap[1] = heap[nheap];
                nheap--;
                {
                    int zz = 0, yy = 0, tmp = 0;
                    zz = 1;
                    tmp = heap[zz];
                    while (true) {
                        yy = zz << 1;
                        if (yy > nheap) {
                            break;
                        }
                        if (yy < nheap
                            && weight[heap[yy + 1]] < weight[heap[yy]]) {
                            yy++;
                        }
                        if (weight[tmp] < weight[heap[yy]]) {
                            break;
                        }
                        heap[zz] = heap[yy];
                        zz = yy;
                    }
                    heap[zz] = tmp;
                }
                nnodes++;
                parent[n1] = parent[n2] = nnodes;

                weight[nnodes] = ((weight[n1] & 0xffffff00)
                                  + (weight[n2] & 0xffffff00))
                    | (1 + (((weight[n1] & 0x000000ff) >
                             (weight[n2] & 0x000000ff)) ?
                            (weight[n1] & 0x000000ff) :
                            (weight[n2] & 0x000000ff)));

                parent[nnodes] = -1;
                nheap++;
                heap[nheap] = nnodes;
                {
                    int zz = 0, tmp = 0;
                    zz = nheap;
                    tmp = heap[zz];
                    while (weight[tmp] < weight[heap[zz >> 1]]) {
                        heap[zz] = heap[zz >> 1];
                        zz >>= 1;
                    }
                    heap[zz] = tmp;
                }
            }
            if (!(nnodes < (max_alpha_size * 2))) {
                panic();
            }

            toolong = false;
            for (i = 1; i <= alphasize; i++) {
                j = 0;
                k = i;
                while (parent[k] >= 0) {
                    k = parent[k];
                    j++;
                }
                len[i - 1] = (char) j;
                if (j > maxlen) {
                    toolong = true;
                }
            }

            if (!toolong) {
                break;
            }

            for (i = 1; i < alphasize; i++) {
                j = weight[i] >> 8;
                j = 1 + (j / 2);
                weight[i] = j << 8;
            }
        }
    }

    /*
      index of the last char in the block, so
      the block size == last + 1.
    */
    int last;

    /*
      index in zptr[] of original string after sorting.
    */
    int origptr;

    /*
      always: in the range 0 .. 9.
      the current block size is 100000 * this number.
    */
    int blocksize100k;

    boolean blockrandomised;

    int bytesout;
    int bsbuff;
    int bslive;
    crc mcrc = new crc();

    private boolean[] inuse = new boolean[256];
    private int ninuse;

    private char[] seqtounseq = new char[256];
    private char[] unseqtoseq = new char[256];

    private char[] selector = new char[max_selectors];
    private char[] selectormtf = new char[max_selectors];

    private char[] block;
    private int[] quadrant;
    private int[] zptr;
    private short[] szptr;
    private int[] ftab;

    private int nmtf;

    private int[] mtffreq = new int[max_alpha_size];

    /*
     * used when sorting.  if too many long comparisons
     * happen, we stop sorting, randomise the block
     * slightly, and try again.
     */
    private int workfactor;
    private int workdone;
    private int worklimit;
    private boolean firstattempt;
    private int nblocksrandomised;

    private int currentchar = -1;
    private int runlength = 0;

    public cbzip2outputstream(outputstream instream) throws ioexception {
        this(instream, 9);
    }

    public cbzip2outputstream(outputstream instream, int inblocksize)
        throws ioexception {
        block = null;
        quadrant = null;
        zptr = null;
        ftab = null;

        instream.write('b');
        instream.write('z');

        bssetstream(instream);

        workfactor = 50;
        if (inblocksize > 9) {
            inblocksize = 9;
        }
        if (inblocksize < 1) {
            inblocksize = 1;
        }
        blocksize100k = inblocksize;
        allocatecompressstructures();
        initialize();
        initblock();
    }

    /**
     *
     * modified by oliver merkel, 010128
     *
     */
    public void write(int bv) throws ioexception {
        int b = (256 + bv) % 256;
        if (currentchar != -1) {
            if (currentchar == b) {
                runlength++;
                if (runlength > 254) {
                    writerun();
                    currentchar = -1;
                    runlength = 0;
                }
            } else {
                writerun();
                runlength = 1;
                currentchar = b;
            }
        } else {
            currentchar = b;
            runlength++;
        }
    }

    private void writerun() throws ioexception {
        if (last < allowableblocksize) {
            inuse[currentchar] = true;
            for (int i = 0; i < runlength; i++) {
                mcrc.updatecrc((char) currentchar);
            }
            switch (runlength) {
            case 1:
                last++;
                block[last + 1] = (char) currentchar;
                break;
            case 2:
                last++;
                block[last + 1] = (char) currentchar;
                last++;
                block[last + 1] = (char) currentchar;
                break;
            case 3:
                last++;
                block[last + 1] = (char) currentchar;
                last++;
                block[last + 1] = (char) currentchar;
                last++;
                block[last + 1] = (char) currentchar;
                break;
            default:
                inuse[runlength - 4] = true;
                last++;
                block[last + 1] = (char) currentchar;
                last++;
                block[last + 1] = (char) currentchar;
                last++;
                block[last + 1] = (char) currentchar;
                last++;
                block[last + 1] = (char) currentchar;
                last++;
                block[last + 1] = (char) (runlength - 4);
                break;
            }
        } else {
            endblock();
            initblock();
            writerun();
        }
    }

    boolean closed = false;

    protected void finalize() throws throwable {
        close();
        super.finalize();
    }

    public void close() throws ioexception {
        if (closed) {
            return;
        }

        finish();

        closed = true;
        super.close();
        bsstream.close();
    }

    public void finish() throws ioexception {
        if (finished) {
            return;
        }

        if (runlength > 0) {
            writerun();
        }
        currentchar = -1;
        endblock();
        endcompression();
        finished = true;
        flush();
    }
    
    public void flush() throws ioexception {
        super.flush();
        bsstream.flush();
    }

    private int blockcrc, combinedcrc;

    private void initialize() throws ioexception {
        bytesout = 0;
        nblocksrandomised = 0;

        /* write `magic' bytes h indicating file-format == huffmanised,
           followed by a digit indicating blocksize100k.
        */
        bsputuchar('h');
        bsputuchar('0' + blocksize100k);

        combinedcrc = 0;
    }

    private int allowableblocksize;

    private void initblock() {
        //        blockno++;
        mcrc.initialisecrc();
        last = -1;
        //        ch = 0;

        for (int i = 0; i < 256; i++) {
            inuse[i] = false;
        }

        /* 20 is just a paranoia constant */
        allowableblocksize = baseblocksize * blocksize100k - 20;
    }

    private void endblock() throws ioexception {
        blockcrc = mcrc.getfinalcrc();
        combinedcrc = (combinedcrc << 1) | (combinedcrc >>> 31);
        combinedcrc ^= blockcrc;

        /* sort the block and establish posn of original string */
        doreversibletransformation();

        /*
          a 6-byte block header, the value chosen arbitrarily
          as 0x314159265359 :-).  a 32 bit value does not really
          give a strong enough guarantee that the value will not
          appear by chance in the compressed datastream.  worst-case
          probability of this event, for a 900k block, is about
          2.0e-3 for 32 bits, 1.0e-5 for 40 bits and 4.0e-8 for 48 bits.
          for a compressed file of size 100gb -- about 100000 blocks --
          only a 48-bit marker will do.  nb: normal compression/
          decompression do *not* rely on these statistical properties.
          they are only important when trying to recover blocks from
          damaged files.
        */
        bsputuchar(0x31);
        bsputuchar(0x41);
        bsputuchar(0x59);
        bsputuchar(0x26);
        bsputuchar(0x53);
        bsputuchar(0x59);

        /* now the block's crc, so it is in a known place. */
        bsputint(blockcrc);

        /* now a single bit indicating randomisation. */
        if (blockrandomised) {
            bsw(1, 1);
            nblocksrandomised++;
        } else {
            bsw(1, 0);
        }

        /* finally, block's contents proper. */
        movetofrontcodeandsend();
    }

    private void endcompression() throws ioexception {
        /*
          now another magic 48-bit number, 0x177245385090, to
          indicate the end of the last block.  (sqrt(pi), if
          you want to know.  i did want to use e, but it contains
          too much repetition -- 27 18 28 18 28 46 -- for me
          to feel statistically comfortable.  call me paranoid.)
        */
        bsputuchar(0x17);
        bsputuchar(0x72);
        bsputuchar(0x45);
        bsputuchar(0x38);
        bsputuchar(0x50);
        bsputuchar(0x90);

        bsputint(combinedcrc);

        bsfinishedwithstream();
    }

    private void hbassigncodes (int[] code, char[] length, int minlen,
                                int maxlen, int alphasize) {
        int n, vec, i;

        vec = 0;
        for (n = minlen; n <= maxlen; n++) {
            for (i = 0; i < alphasize; i++) {
                if (length[i] == n) {
                    code[i] = vec;
                    vec++;
                }
            }
            vec <<= 1;
        }
    }

    private void bssetstream(outputstream f) {
        bsstream = f;
        bslive = 0;
        bsbuff = 0;
        bytesout = 0;
    }

    private void bsfinishedwithstream() throws ioexception {
        while (bslive > 0) {
            int ch = (bsbuff >> 24);
            try {
                bsstream.write(ch); // write 8-bit
            } catch (ioexception e) {
                throw  e;
            }
            bsbuff <<= 8;
            bslive -= 8;
            bytesout++;
        }
    }

    private void bsw(int n, int v) throws ioexception {
        while (bslive >= 8) {
            int ch = (bsbuff >> 24);
            try {
                bsstream.write(ch); // write 8-bit
            } catch (ioexception e) {
                throw e;
            }
            bsbuff <<= 8;
            bslive -= 8;
            bytesout++;
        }
        bsbuff |= (v << (32 - bslive - n));
        bslive += n;
    }

    private void bsputuchar(int c) throws ioexception {
        bsw(8, c);
    }

    private void bsputint(int u) throws ioexception {
        bsw(8, (u >> 24) & 0xff);
        bsw(8, (u >> 16) & 0xff);
        bsw(8, (u >>  8) & 0xff);
        bsw(8,  u        & 0xff);
    }

    private void bsputintvs(int numbits, int c) throws ioexception {
        bsw(numbits, c);
    }

    private void sendmtfvalues() throws ioexception {
        char len[][] = new char[n_groups][max_alpha_size];

        int v, t, i, j, gs, ge, totc, bt, bc, iter;
        int nselectors = 0, alphasize, minlen, maxlen, selctr;
        int ngroups;//, nbytes;

        alphasize = ninuse + 2;
        for (t = 0; t < n_groups; t++) {
            for (v = 0; v < alphasize; v++) {
                len[t][v] = (char) greater_icost;
            }
        }

        /* decide how many coding tables to use */
        if (nmtf <= 0) {
            panic();
        }

        if (nmtf < 200) {
            ngroups = 2;
        } else if (nmtf < 600) {
            ngroups = 3;
        } else if (nmtf < 1200) {
            ngroups = 4;
        } else if (nmtf < 2400) {
            ngroups = 5;
        } else {
            ngroups = 6;
        }

        /* generate an initial set of coding tables */ {
            int npart, remf, tfreq, afreq;

            npart = ngroups;
            remf  = nmtf;
            gs = 0;
            while (npart > 0) {
                tfreq = remf / npart;
                ge = gs - 1;
                afreq = 0;
                while (afreq < tfreq && ge < alphasize - 1) {
                    ge++;
                    afreq += mtffreq[ge];
                }

                if (ge > gs && npart != ngroups && npart != 1
                    && ((ngroups - npart) % 2 == 1)) {
                    afreq -= mtffreq[ge];
                    ge--;
                }

                for (v = 0; v < alphasize; v++) {
                    if (v >= gs && v <= ge) {
                        len[npart - 1][v] = (char) lesser_icost;
                    } else {
                        len[npart - 1][v] = (char) greater_icost;
                    }
                }

                npart--;
                gs = ge + 1;
                remf -= afreq;
            }
        }

        int[][] rfreq = new int[n_groups][max_alpha_size];
        int[] fave = new int[n_groups];
        short[] cost = new short[n_groups];
        /*
          iterate up to n_iters times to improve the tables.
        */
        for (iter = 0; iter < n_iters; iter++) {
            for (t = 0; t < ngroups; t++) {
                fave[t] = 0;
            }

            for (t = 0; t < ngroups; t++) {
                for (v = 0; v < alphasize; v++) {
                    rfreq[t][v] = 0;
                }
            }

            nselectors = 0;
            totc = 0;
            gs = 0;
            while (true) {

                /* set group start & end marks. */
                if (gs >= nmtf) {
                    break;
                }
                ge = gs + g_size - 1;
                if (ge >= nmtf) {
                    ge = nmtf - 1;
                }

                /*
                  calculate the cost of this group as coded
                  by each of the coding tables.
                */
                for (t = 0; t < ngroups; t++) {
                    cost[t] = 0;
                }

                if (ngroups == 6) {
                    short cost0, cost1, cost2, cost3, cost4, cost5;
                    cost0 = cost1 = cost2 = cost3 = cost4 = cost5 = 0;
                    for (i = gs; i <= ge; i++) {
                        short icv = szptr[i];
                        cost0 += len[0][icv];
                        cost1 += len[1][icv];
                        cost2 += len[2][icv];
                        cost3 += len[3][icv];
                        cost4 += len[4][icv];
                        cost5 += len[5][icv];
                    }
                    cost[0] = cost0;
                    cost[1] = cost1;
                    cost[2] = cost2;
                    cost[3] = cost3;
                    cost[4] = cost4;
                    cost[5] = cost5;
                } else {
                    for (i = gs; i <= ge; i++) {
                        short icv = szptr[i];
                        for (t = 0; t < ngroups; t++) {
                            cost[t] += len[t][icv];
                        }
                    }
                }

                /*
                  find the coding table which is best for this group,
                  and record its identity in the selector table.
                */
                bc = 999999999;
                bt = -1;
                for (t = 0; t < ngroups; t++) {
                    if (cost[t] < bc) {
                        bc = cost[t];
                        bt = t;
                    }
                }
                totc += bc;
                fave[bt]++;
                selector[nselectors] = (char) bt;
                nselectors++;

                /*
                  increment the symbol frequencies for the selected table.
                */
                for (i = gs; i <= ge; i++) {
                    rfreq[bt][szptr[i]]++;
                }

                gs = ge + 1;
            }

            /*
              recompute the tables based on the accumulated frequencies.
            */
            for (t = 0; t < ngroups; t++) {
                hbmakecodelengths(len[t], rfreq[t], alphasize, 20);
            }
        }

        rfreq = null;
        fave = null;
        cost = null;

        if (!(ngroups < 8)) {
            panic();
        }
        if (!(nselectors < 32768 && nselectors <= (2 + (900000 / g_size)))) {
            panic();
        }


        /* compute mtf values for the selectors. */
        {
            char[] pos = new char[n_groups];
            char ll_i, tmp2, tmp;
            for (i = 0; i < ngroups; i++) {
                pos[i] = (char) i;
            }
            for (i = 0; i < nselectors; i++) {
                ll_i = selector[i];
                j = 0;
                tmp = pos[j];
                while (ll_i != tmp) {
                    j++;
                    tmp2 = tmp;
                    tmp = pos[j];
                    pos[j] = tmp2;
                }
                pos[0] = tmp;
                selectormtf[i] = (char) j;
            }
        }

        int[][] code = new int[n_groups][max_alpha_size];

        /* assign actual codes for the tables. */
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
            if (maxlen > 20) {
                panic();
            }
            if (minlen < 1) {
                panic();
            }
            hbassigncodes(code[t], len[t], minlen, maxlen, alphasize);
        }

        /* transmit the mapping table. */
        {
            boolean[] inuse16 = new boolean[16];
            for (i = 0; i < 16; i++) {
                inuse16[i] = false;
                for (j = 0; j < 16; j++) {
                    if (inuse[i * 16 + j]) {
                        inuse16[i] = true;
                    }
                }
            }

//            nbytes = bytesout;
            for (i = 0; i < 16; i++) {
                if (inuse16[i]) {
                    bsw(1, 1);
                } else {
                    bsw(1, 0);
                }
            }

            for (i = 0; i < 16; i++) {
                if (inuse16[i]) {
                    for (j = 0; j < 16; j++) {
                        if (inuse[i * 16 + j]) {
                            bsw(1, 1);
                        } else {
                            bsw(1, 0);
                        }
                    }
                }
            }

        }

        /* now the selectors. */
//        nbytes = bytesout;
        bsw (3, ngroups);
        bsw (15, nselectors);
        for (i = 0; i < nselectors; i++) {
            for (j = 0; j < selectormtf[i]; j++) {
                bsw(1, 1);
            }
            bsw(1, 0);
        }

        /* now the coding tables. */
//        nbytes = bytesout;

        for (t = 0; t < ngroups; t++) {
            int curr = len[t][0];
            bsw(5, curr);
            for (i = 0; i < alphasize; i++) {
                while (curr < len[t][i]) {
                    bsw(2, 2);
                    curr++; /* 10 */
                }
                while (curr > len[t][i]) {
                    bsw(2, 3);
                    curr--; /* 11 */
                }
                bsw (1, 0);
            }
        }

        /* and finally, the block data proper */
//        nbytes = bytesout;
        selctr = 0;
        gs = 0;
        while (true) {
            if (gs >= nmtf) {
                break;
            }
            ge = gs + g_size - 1;
            if (ge >= nmtf) {
                ge = nmtf - 1;
            }
            for (i = gs; i <= ge; i++) {
                bsw(len[selector[selctr]][szptr[i]],
                    code[selector[selctr]][szptr[i]]);
            }

            gs = ge + 1;
            selctr++;
        }
        if (!(selctr == nselectors)) {
            panic();
        }
    }

    private void movetofrontcodeandsend () throws ioexception {
        bsputintvs(24, origptr);
        generatemtfvalues();
        sendmtfvalues();
    }

    private outputstream bsstream;

    private void simplesort(int lo, int hi, int d) {
        int i, j, h, bign, hp;
        int v;

        bign = hi - lo + 1;
        if (bign < 2) {
            return;
        }

        hp = 0;
        while (incs[hp] < bign) {
            hp++;
        }
        hp--;

        for (; hp >= 0; hp--) {
            h = incs[hp];

            i = lo + h;
            while (true) {
                /* copy 1 */
                if (i > hi) {
                    break;
                }
                v = zptr[i];
                j = i;
                while (fullgtu(zptr[j - h] + d, v + d)) {
                    zptr[j] = zptr[j - h];
                    j = j - h;
                    if (j <= (lo + h - 1)) {
                        break;
                    }
                }
                zptr[j] = v;
                i++;

                /* copy 2 */
                if (i > hi) {
                    break;
                }
                v = zptr[i];
                j = i;
                while (fullgtu(zptr[j - h] + d, v + d)) {
                    zptr[j] = zptr[j - h];
                    j = j - h;
                    if (j <= (lo + h - 1)) {
                        break;
                    }
                }
                zptr[j] = v;
                i++;

                /* copy 3 */
                if (i > hi) {
                    break;
                }
                v = zptr[i];
                j = i;
                while (fullgtu(zptr[j - h] + d, v + d)) {
                    zptr[j] = zptr[j - h];
                    j = j - h;
                    if (j <= (lo + h - 1)) {
                        break;
                    }
                }
                zptr[j] = v;
                i++;

                if (workdone > worklimit && firstattempt) {
                    return;
                }
            }
        }
    }

    private void vswap(int p1, int p2, int n) {
        int temp = 0;
        while (n > 0) {
            temp = zptr[p1];
            zptr[p1] = zptr[p2];
            zptr[p2] = temp;
            p1++;
            p2++;
            n--;
        }
    }

    private char med3(char a, char b, char c) {
        char t;
        if (a > b) {
            t = a;
            a = b;
            b = t;
        }
        if (b > c) {
            t = b;
            b = c;
            c = t;
        }
        if (a > b) {
            b = a;
        }
        return b;
    }

    private static class stackelem {
        int ll;
        int hh;
        int dd;
    }

    private void qsort3(int lost, int hist, int dst) {
        int unlo, unhi, ltlo, gthi, med, n, m;
        int sp, lo, hi, d;
        stackelem[] stack = new stackelem[qsort_stack_size];
        for (int count = 0; count < qsort_stack_size; count++) {
            stack[count] = new stackelem();
        }

        sp = 0;

        stack[sp].ll = lost;
        stack[sp].hh = hist;
        stack[sp].dd = dst;
        sp++;

        while (sp > 0) {
            if (sp >= qsort_stack_size) {
                panic();
            }

            sp--;
            lo = stack[sp].ll;
            hi = stack[sp].hh;
            d = stack[sp].dd;

            if (hi - lo < small_thresh || d > depth_thresh) {
                simplesort(lo, hi, d);
                if (workdone > worklimit && firstattempt) {
                    return;
                }
                continue;
            }

            med = med3(block[zptr[lo] + d + 1],
                       block[zptr[hi            ] + d  + 1],
                       block[zptr[(lo + hi) >> 1] + d + 1]);

            unlo = ltlo = lo;
            unhi = gthi = hi;

            while (true) {
                while (true) {
                    if (unlo > unhi) {
                        break;
                    }
                    n = ((int) block[zptr[unlo] + d + 1]) - med;
                    if (n == 0) {
                        int temp = 0;
                        temp = zptr[unlo];
                        zptr[unlo] = zptr[ltlo];
                        zptr[ltlo] = temp;
                        ltlo++;
                        unlo++;
                        continue;
                    }
                    if (n >  0) {
                        break;
                    }
                    unlo++;
                }
                while (true) {
                    if (unlo > unhi) {
                        break;
                    }
                    n = ((int) block[zptr[unhi] + d + 1]) - med;
                    if (n == 0) {
                        int temp = 0;
                        temp = zptr[unhi];
                        zptr[unhi] = zptr[gthi];
                        zptr[gthi] = temp;
                        gthi--;
                        unhi--;
                        continue;
                    }
                    if (n <  0) {
                        break;
                    }
                    unhi--;
                }
                if (unlo > unhi) {
                    break;
                }
                int temp = 0;
                temp = zptr[unlo];
                zptr[unlo] = zptr[unhi];
                zptr[unhi] = temp;
                unlo++;
                unhi--;
            }

            if (gthi < ltlo) {
                stack[sp].ll = lo;
                stack[sp].hh = hi;
                stack[sp].dd = d + 1;
                sp++;
                continue;
            }

            n = ((ltlo - lo) < (unlo - ltlo)) ? (ltlo - lo) : (unlo - ltlo);
            vswap(lo, unlo - n, n);
            m = ((hi - gthi) < (gthi - unhi)) ? (hi - gthi) : (gthi - unhi);
            vswap(unlo, hi - m + 1, m);

            n = lo + unlo - ltlo - 1;
            m = hi - (gthi - unhi) + 1;

            stack[sp].ll = lo;
            stack[sp].hh = n;
            stack[sp].dd = d;
            sp++;

            stack[sp].ll = n + 1;
            stack[sp].hh = m - 1;
            stack[sp].dd = d + 1;
            sp++;

            stack[sp].ll = m;
            stack[sp].hh = hi;
            stack[sp].dd = d;
            sp++;
        }
    }

    private void mainsort() {
        int i, j, ss, sb;
        int[] runningorder = new int[256];
        int[] copy = new int[256];
        boolean[] bigdone = new boolean[256];
        int c1, c2;
        int numqsorted;

        /*
          in the various block-sized structures, live data runs
          from 0 to last+num_overshoot_bytes inclusive.  first,
          set up the overshoot area for block.
        */

        //   if (verbosity >= 4) fprintf ( stderr, "   sort initialise ...\n" );
        for (i = 0; i < num_overshoot_bytes; i++) {
            block[last + i + 2] = block[(i % (last + 1)) + 1];
        }
        for (i = 0; i <= last + num_overshoot_bytes; i++) {
            quadrant[i] = 0;
        }

        block[0] = (char) (block[last + 1]);

        if (last < 4000) {
            /*
              use simplesort(), since the full sorting mechanism
              has quite a large constant overhead.
            */
            for (i = 0; i <= last; i++) {
                zptr[i] = i;
            }
            firstattempt = false;
            workdone = worklimit = 0;
            simplesort(0, last, 0);
        } else {
            numqsorted = 0;
            for (i = 0; i <= 255; i++) {
                bigdone[i] = false;
            }

            for (i = 0; i <= 65536; i++) {
                ftab[i] = 0;
            }

            c1 = block[0];
            for (i = 0; i <= last; i++) {
                c2 = block[i + 1];
                ftab[(c1 << 8) + c2]++;
                c1 = c2;
            }

            for (i = 1; i <= 65536; i++) {
                ftab[i] += ftab[i - 1];
            }

            c1 = block[1];
            for (i = 0; i < last; i++) {
                c2 = block[i + 2];
                j = (c1 << 8) + c2;
                c1 = c2;
                ftab[j]--;
                zptr[ftab[j]] = i;
            }

            j = ((block[last + 1]) << 8) + (block[1]);
            ftab[j]--;
            zptr[ftab[j]] = last;

            /*
              now ftab contains the first loc of every small bucket.
              calculate the running order, from smallest to largest
              big bucket.
            */

            for (i = 0; i <= 255; i++) {
                runningorder[i] = i;
            }

            {
                int vv;
                int h = 1;
                do {
                    h = 3 * h + 1;
                }
                while (h <= 256);
                do {
                    h = h / 3;
                    for (i = h; i <= 255; i++) {
                        vv = runningorder[i];
                        j = i;
                        while ((ftab[((runningorder[j - h]) + 1) << 8]
                                - ftab[(runningorder[j - h]) << 8]) >
                               (ftab[((vv) + 1) << 8] - ftab[(vv) << 8])) {
                            runningorder[j] = runningorder[j - h];
                            j = j - h;
                            if (j <= (h - 1)) {
                                break;
                            }
                        }
                        runningorder[j] = vv;
                    }
                } while (h != 1);
            }

            /*
              the main sorting loop.
            */
            for (i = 0; i <= 255; i++) {

                /*
                  process big buckets, starting with the least full.
                */
                ss = runningorder[i];

                /*
                  complete the big bucket [ss] by quicksorting
                  any unsorted small buckets [ss, j].  hopefully
                  previous pointer-scanning phases have already
                  completed many of the small buckets [ss, j], so
                  we don't have to sort them at all.
                */
                for (j = 0; j <= 255; j++) {
                    sb = (ss << 8) + j;
                    if (!((ftab[sb] & setmask) == setmask)) {
                        int lo = ftab[sb] & clearmask;
                        int hi = (ftab[sb + 1] & clearmask) - 1;
                        if (hi > lo) {
                            qsort3(lo, hi, 2);
                            numqsorted += (hi - lo + 1);
                            if (workdone > worklimit && firstattempt) {
                                return;
                            }
                        }
                        ftab[sb] |= setmask;
                    }
                }

                /*
                  the ss big bucket is now done.  record this fact,
                  and update the quadrant descriptors.  remember to
                  update quadrants in the overshoot area too, if
                  necessary.  the "if (i < 255)" test merely skips
                  this updating for the last bucket processed, since
                  updating for the last bucket is pointless.
                */
                bigdone[ss] = true;

                if (i < 255) {
                    int bbstart  = ftab[ss << 8] & clearmask;
                    int bbsize   = (ftab[(ss + 1) << 8] & clearmask) - bbstart;
                    int shifts   = 0;

                    while ((bbsize >> shifts) > 65534) {
                        shifts++;
                    }

                    for (j = 0; j < bbsize; j++) {
                        int a2update = zptr[bbstart + j];
                        int qval = (j >> shifts);
                        quadrant[a2update] = qval;
                        if (a2update < num_overshoot_bytes) {
                            quadrant[a2update + last + 1] = qval;
                        }
                    }

                    if (!(((bbsize - 1) >> shifts) <= 65535)) {
                        panic();
                    }
                }

                /*
                  now scan this big bucket so as to synthesise the
                  sorted order for small buckets [t, ss] for all t != ss.
                */
                for (j = 0; j <= 255; j++) {
                    copy[j] = ftab[(j << 8) + ss] & clearmask;
                }

                for (j = ftab[ss << 8] & clearmask;
                     j < (ftab[(ss + 1) << 8] & clearmask); j++) {
                    c1 = block[zptr[j]];
                    if (!bigdone[c1]) {
                        zptr[copy[c1]] = zptr[j] == 0 ? last : zptr[j] - 1;
                        copy[c1]++;
                    }
                }

                for (j = 0; j <= 255; j++) {
                    ftab[(j << 8) + ss] |= setmask;
                }
            }
        }
    }

    private void randomiseblock() {
        int i;
        int rntogo = 0;
        int rtpos  = 0;
        for (i = 0; i < 256; i++) {
            inuse[i] = false;
        }

        for (i = 0; i <= last; i++) {
            if (rntogo == 0) {
                rntogo = (char) rnums[rtpos];
                rtpos++;
                if (rtpos == 512) {
                    rtpos = 0;
                }
            }
            rntogo--;
            block[i + 1] ^= ((rntogo == 1) ? 1 : 0);
            // handle 16 bit signed numbers
            block[i + 1] &= 0xff;

            inuse[block[i + 1]] = true;
        }
    }

    private void doreversibletransformation() {
        int i;

        worklimit = workfactor * last;
        workdone = 0;
        blockrandomised = false;
        firstattempt = true;

        mainsort();

        if (workdone > worklimit && firstattempt) {
            randomiseblock();
            worklimit = workdone = 0;
            blockrandomised = true;
            firstattempt = false;
            mainsort();
        }

        origptr = -1;
        for (i = 0; i <= last; i++) {
            if (zptr[i] == 0) {
                origptr = i;
                break;
            }
        }

        if (origptr == -1) {
            panic();
        }
    }

    private boolean fullgtu(int i1, int i2) {
        int k;
        char c1, c2;
        int s1, s2;

        c1 = block[i1 + 1];
        c2 = block[i2 + 1];
        if (c1 != c2) {
            return (c1 > c2);
        }
        i1++;
        i2++;

        c1 = block[i1 + 1];
        c2 = block[i2 + 1];
        if (c1 != c2) {
            return (c1 > c2);
        }
        i1++;
        i2++;

        c1 = block[i1 + 1];
        c2 = block[i2 + 1];
        if (c1 != c2) {
            return (c1 > c2);
        }
        i1++;
        i2++;

        c1 = block[i1 + 1];
        c2 = block[i2 + 1];
        if (c1 != c2) {
            return (c1 > c2);
        }
        i1++;
        i2++;

        c1 = block[i1 + 1];
        c2 = block[i2 + 1];
        if (c1 != c2) {
            return (c1 > c2);
        }
        i1++;
        i2++;

        c1 = block[i1 + 1];
        c2 = block[i2 + 1];
        if (c1 != c2) {
            return (c1 > c2);
        }
        i1++;
        i2++;

        k = last + 1;

        do {
            c1 = block[i1 + 1];
            c2 = block[i2 + 1];
            if (c1 != c2) {
                return (c1 > c2);
            }
            s1 = quadrant[i1];
            s2 = quadrant[i2];
            if (s1 != s2) {
                return (s1 > s2);
            }
            i1++;
            i2++;

            c1 = block[i1 + 1];
            c2 = block[i2 + 1];
            if (c1 != c2) {
                return (c1 > c2);
            }
            s1 = quadrant[i1];
            s2 = quadrant[i2];
            if (s1 != s2) {
                return (s1 > s2);
            }
            i1++;
            i2++;

            c1 = block[i1 + 1];
            c2 = block[i2 + 1];
            if (c1 != c2) {
                return (c1 > c2);
            }
            s1 = quadrant[i1];
            s2 = quadrant[i2];
            if (s1 != s2) {
                return (s1 > s2);
            }
            i1++;
            i2++;

            c1 = block[i1 + 1];
            c2 = block[i2 + 1];
            if (c1 != c2) {
                return (c1 > c2);
            }
            s1 = quadrant[i1];
            s2 = quadrant[i2];
            if (s1 != s2) {
                return (s1 > s2);
            }
            i1++;
            i2++;

            if (i1 > last) {
                i1 -= last;
                i1--;
            }
            if (i2 > last) {
                i2 -= last;
                i2--;
            }

            k -= 4;
            workdone++;
        } while (k >= 0);

        return false;
    }

    /*
      knuth's increments seem to work better
      than incerpi-sedgewick here.  possibly
      because the number of elems to sort is
      usually small, typically <= 20.
    */
    private int[] incs = { 1, 4, 13, 40, 121, 364, 1093, 3280,
                           9841, 29524, 88573, 265720,
                           797161, 2391484 };

    private void allocatecompressstructures () {
        int n = baseblocksize * blocksize100k;
        block = new char[(n + 1 + num_overshoot_bytes)];
        quadrant = new int[(n + num_overshoot_bytes)];
        zptr = new int[n];
        ftab = new int[65537];

        if (block == null || quadrant == null || zptr == null
            || ftab == null) {
            //int totaldraw = (n + 1 + num_overshoot_bytes) + (n + num_overshoot_bytes) + n + 65537;
            //compressoutofmemory ( totaldraw, n );
        }

        /*
          the back end needs a place to store the mtf values
          whilst it calculates the coding tables.  we could
          put them in the zptr array.  however, these values
          will fit in a short, so we overlay szptr at the
          start of zptr, in the hope of reducing the number
          of cache misses induced by the multiple traversals
          of the mtf values when calculating coding tables.
          seems to improve compression speed by about 1%.
        */
        //    szptr = zptr;


        szptr = new short[2 * n];
    }

    private void generatemtfvalues() {
        char[] yy = new char[256];
        int  i, j;
        char tmp;
        char tmp2;
        int zpend;
        int wr;
        int eob;

        makemaps();
        eob = ninuse + 1;

        for (i = 0; i <= eob; i++) {
            mtffreq[i] = 0;
        }

        wr = 0;
        zpend = 0;
        for (i = 0; i < ninuse; i++) {
            yy[i] = (char) i;
        }


        for (i = 0; i <= last; i++) {
            char ll_i;

            ll_i = unseqtoseq[block[zptr[i]]];

            j = 0;
            tmp = yy[j];
            while (ll_i != tmp) {
                j++;
                tmp2 = tmp;
                tmp = yy[j];
                yy[j] = tmp2;
            }
            yy[0] = tmp;

            if (j == 0) {
                zpend++;
            } else {
                if (zpend > 0) {
                    zpend--;
                    while (true) {
                        switch (zpend % 2) {
                        case 0:
                            szptr[wr] = (short) runa;
                            wr++;
                            mtffreq[runa]++;
                            break;
                        case 1:
                            szptr[wr] = (short) runb;
                            wr++;
                            mtffreq[runb]++;
                            break;
                        }
                        if (zpend < 2) {
                            break;
                        }
                        zpend = (zpend - 2) / 2;
                    }
                    zpend = 0;
                }
                szptr[wr] = (short) (j + 1);
                wr++;
                mtffreq[j + 1]++;
            }
        }

        if (zpend > 0) {
            zpend--;
            while (true) {
                switch (zpend % 2) {
                case 0:
                    szptr[wr] = (short) runa;
                    wr++;
                    mtffreq[runa]++;
                    break;
                case 1:
                    szptr[wr] = (short) runb;
                    wr++;
                    mtffreq[runb]++;
                    break;
                }
                if (zpend < 2) {
                    break;
                }
                zpend = (zpend - 2) / 2;
            }
        }

        szptr[wr] = (short) eob;
        wr++;
        mtffreq[eob]++;

        nmtf = wr;
    }
}


