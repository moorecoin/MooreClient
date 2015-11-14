package org.ripple.bouncycastle.crypto.engines;

import org.ripple.bouncycastle.crypto.blockcipher;
import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.datalengthexception;
import org.ripple.bouncycastle.crypto.outputlengthexception;
import org.ripple.bouncycastle.crypto.params.keyparameter;

/**
 * serpent is a 128-bit 32-round block cipher with variable key lengths,
 * including 128, 192 and 256 bit keys conjectured to be at least as
 * secure as three-key triple-des.
 * <p>
 * serpent was designed by ross anderson, eli biham and lars knudsen as a
 * candidate algorithm for the nist aes quest.>
 * <p>
 * for full details see the <a href="http://www.cl.cam.ac.uk/~rja14/serpent.html">the serpent home page</a>
 */
public class serpentengine
    implements blockcipher
{
    private static final int    block_size = 16;

    static final int rounds = 32;
    static final int phi    = 0x9e3779b9;       // (sqrt(5) - 1) * 2**31

    private boolean        encrypting;
    private int[]          wkey;

    private int           x0, x1, x2, x3;    // registers

    /**
     * initialise a serpent cipher.
     *
     * @param encrypting whether or not we are for encryption.
     * @param params the parameters required to set up the cipher.
     * @exception illegalargumentexception if the params argument is
     * inappropriate.
     */
    public void init(
        boolean             encrypting,
        cipherparameters    params)
    {
        if (params instanceof keyparameter)
        {
            this.encrypting = encrypting;
            this.wkey = makeworkingkey(((keyparameter)params).getkey());
            return;
        }

        throw new illegalargumentexception("invalid parameter passed to serpent init - " + params.getclass().getname());
    }

    public string getalgorithmname()
    {
        return "serpent";
    }

    public int getblocksize()
    {
        return block_size;
    }

    /**
     * process one block of input from the array in and write it to
     * the out array.
     *
     * @param in the array containing the input data.
     * @param inoff offset into the in array the data starts at.
     * @param out the array the output data will be copied into.
     * @param outoff the offset into the out array the output will start at.
     * @exception datalengthexception if there isn't enough data in in, or
     * space in out.
     * @exception illegalstateexception if the cipher isn't initialised.
     * @return the number of bytes processed and produced.
     */
    public final int processblock(
        byte[]  in,
        int     inoff,
        byte[]  out,
        int     outoff)
    {
        if (wkey == null)
        {
            throw new illegalstateexception("serpent not initialised");
        }

        if ((inoff + block_size) > in.length)
        {
            throw new datalengthexception("input buffer too short");
        }

        if ((outoff + block_size) > out.length)
        {
            throw new outputlengthexception("output buffer too short");
        }

        if (encrypting)
        {
            encryptblock(in, inoff, out, outoff);
        }
        else
        {
            decryptblock(in, inoff, out, outoff);
        }

        return block_size;
    }

    public void reset()
    {
    }

    /**
     * expand a user-supplied key material into a session key.
     *
     * @param key  the user-key bytes (multiples of 4) to use.
     * @exception illegalargumentexception
     */
    private int[] makeworkingkey(
        byte[] key)
    throws  illegalargumentexception
    {
        //
        // pad key to 256 bits
        //
        int[]   kpad = new int[16];
        int     off = 0;
        int     length = 0;

        for (off = key.length - 4; off > 0; off -= 4)
        {
            kpad[length++] = bytestoword(key, off);
        }

        if (off == 0)
        {
            kpad[length++] = bytestoword(key, 0);
            if (length < 8)
            {
                kpad[length] = 1;
            }
        }
        else
        {
            throw new illegalargumentexception("key must be a multiple of 4 bytes");
        }

        //
        // expand the padded key up to 33 x 128 bits of key material
        //
        int     amount = (rounds + 1) * 4;
        int[]   w = new int[amount];

        //
        // compute w0 to w7 from w-8 to w-1
        //
        for (int i = 8; i < 16; i++)
        {
            kpad[i] = rotateleft(kpad[i - 8] ^ kpad[i - 5] ^ kpad[i - 3] ^ kpad[i - 1] ^ phi ^ (i - 8), 11);
        }

        system.arraycopy(kpad, 8, w, 0, 8);

        //
        // compute w8 to w136
        //
        for (int i = 8; i < amount; i++)
        {
            w[i] = rotateleft(w[i - 8] ^ w[i - 5] ^ w[i - 3] ^ w[i - 1] ^ phi ^ i, 11);
        }

        //
        // create the working keys by processing w with the sbox and ip
        //
        sb3(w[0], w[1], w[2], w[3]);
        w[0] = x0; w[1] = x1; w[2] = x2; w[3] = x3; 
        sb2(w[4], w[5], w[6], w[7]);
        w[4] = x0; w[5] = x1; w[6] = x2; w[7] = x3; 
        sb1(w[8], w[9], w[10], w[11]);
        w[8] = x0; w[9] = x1; w[10] = x2; w[11] = x3; 
        sb0(w[12], w[13], w[14], w[15]);
        w[12] = x0; w[13] = x1; w[14] = x2; w[15] = x3; 
        sb7(w[16], w[17], w[18], w[19]);
        w[16] = x0; w[17] = x1; w[18] = x2; w[19] = x3; 
        sb6(w[20], w[21], w[22], w[23]);
        w[20] = x0; w[21] = x1; w[22] = x2; w[23] = x3; 
        sb5(w[24], w[25], w[26], w[27]);
        w[24] = x0; w[25] = x1; w[26] = x2; w[27] = x3; 
        sb4(w[28], w[29], w[30], w[31]);
        w[28] = x0; w[29] = x1; w[30] = x2; w[31] = x3; 
        sb3(w[32], w[33], w[34], w[35]);
        w[32] = x0; w[33] = x1; w[34] = x2; w[35] = x3; 
        sb2(w[36], w[37], w[38], w[39]);
        w[36] = x0; w[37] = x1; w[38] = x2; w[39] = x3; 
        sb1(w[40], w[41], w[42], w[43]);
        w[40] = x0; w[41] = x1; w[42] = x2; w[43] = x3; 
        sb0(w[44], w[45], w[46], w[47]);
        w[44] = x0; w[45] = x1; w[46] = x2; w[47] = x3; 
        sb7(w[48], w[49], w[50], w[51]);
        w[48] = x0; w[49] = x1; w[50] = x2; w[51] = x3; 
        sb6(w[52], w[53], w[54], w[55]);
        w[52] = x0; w[53] = x1; w[54] = x2; w[55] = x3; 
        sb5(w[56], w[57], w[58], w[59]);
        w[56] = x0; w[57] = x1; w[58] = x2; w[59] = x3; 
        sb4(w[60], w[61], w[62], w[63]);
        w[60] = x0; w[61] = x1; w[62] = x2; w[63] = x3; 
        sb3(w[64], w[65], w[66], w[67]);
        w[64] = x0; w[65] = x1; w[66] = x2; w[67] = x3; 
        sb2(w[68], w[69], w[70], w[71]);
        w[68] = x0; w[69] = x1; w[70] = x2; w[71] = x3; 
        sb1(w[72], w[73], w[74], w[75]);
        w[72] = x0; w[73] = x1; w[74] = x2; w[75] = x3; 
        sb0(w[76], w[77], w[78], w[79]);
        w[76] = x0; w[77] = x1; w[78] = x2; w[79] = x3; 
        sb7(w[80], w[81], w[82], w[83]);
        w[80] = x0; w[81] = x1; w[82] = x2; w[83] = x3; 
        sb6(w[84], w[85], w[86], w[87]);
        w[84] = x0; w[85] = x1; w[86] = x2; w[87] = x3; 
        sb5(w[88], w[89], w[90], w[91]);
        w[88] = x0; w[89] = x1; w[90] = x2; w[91] = x3; 
        sb4(w[92], w[93], w[94], w[95]);
        w[92] = x0; w[93] = x1; w[94] = x2; w[95] = x3; 
        sb3(w[96], w[97], w[98], w[99]);
        w[96] = x0; w[97] = x1; w[98] = x2; w[99] = x3; 
        sb2(w[100], w[101], w[102], w[103]);
        w[100] = x0; w[101] = x1; w[102] = x2; w[103] = x3; 
        sb1(w[104], w[105], w[106], w[107]);
        w[104] = x0; w[105] = x1; w[106] = x2; w[107] = x3; 
        sb0(w[108], w[109], w[110], w[111]);
        w[108] = x0; w[109] = x1; w[110] = x2; w[111] = x3; 
        sb7(w[112], w[113], w[114], w[115]);
        w[112] = x0; w[113] = x1; w[114] = x2; w[115] = x3; 
        sb6(w[116], w[117], w[118], w[119]);
        w[116] = x0; w[117] = x1; w[118] = x2; w[119] = x3; 
        sb5(w[120], w[121], w[122], w[123]);
        w[120] = x0; w[121] = x1; w[122] = x2; w[123] = x3; 
        sb4(w[124], w[125], w[126], w[127]);
        w[124] = x0; w[125] = x1; w[126] = x2; w[127] = x3; 
        sb3(w[128], w[129], w[130], w[131]);
        w[128] = x0; w[129] = x1; w[130] = x2; w[131] = x3; 

        return w;
    }

    private int rotateleft(
        int     x,
        int     bits)
    {
        return (x << bits) | (x >>> -bits);
    }

    private int rotateright(
        int     x,
        int     bits)
    {
        return (x >>> bits) | (x << -bits);
    }

    private int bytestoword(
        byte[]  src,
        int     srcoff)
    {
        return (((src[srcoff] & 0xff) << 24) | ((src[srcoff + 1] & 0xff) <<  16) |
          ((src[srcoff + 2] & 0xff) << 8) | ((src[srcoff + 3] & 0xff)));
    }

    private void wordtobytes(
        int     word,
        byte[]  dst,
        int     dstoff)
    {
        dst[dstoff + 3] = (byte)(word);
        dst[dstoff + 2] = (byte)(word >>> 8);
        dst[dstoff + 1] = (byte)(word >>> 16);
        dst[dstoff]     = (byte)(word >>> 24);
    }

    /**
     * encrypt one block of plaintext.
     *
     * @param in the array containing the input data.
     * @param inoff offset into the in array the data starts at.
     * @param out the array the output data will be copied into.
     * @param outoff the offset into the out array the output will start at.
     */
    private void encryptblock(
        byte[]  in,
        int     inoff,
        byte[]  out,
        int     outoff)
    {
        x3 = bytestoword(in, inoff);
        x2 = bytestoword(in, inoff + 4);
        x1 = bytestoword(in, inoff + 8);
        x0 = bytestoword(in, inoff + 12);

        sb0(wkey[0] ^ x0, wkey[1] ^ x1, wkey[2] ^ x2, wkey[3] ^ x3); lt();
        sb1(wkey[4] ^ x0, wkey[5] ^ x1, wkey[6] ^ x2, wkey[7] ^ x3); lt();
        sb2(wkey[8] ^ x0, wkey[9] ^ x1, wkey[10] ^ x2, wkey[11] ^ x3); lt();
        sb3(wkey[12] ^ x0, wkey[13] ^ x1, wkey[14] ^ x2, wkey[15] ^ x3); lt();
        sb4(wkey[16] ^ x0, wkey[17] ^ x1, wkey[18] ^ x2, wkey[19] ^ x3); lt();
        sb5(wkey[20] ^ x0, wkey[21] ^ x1, wkey[22] ^ x2, wkey[23] ^ x3); lt();
        sb6(wkey[24] ^ x0, wkey[25] ^ x1, wkey[26] ^ x2, wkey[27] ^ x3); lt();
        sb7(wkey[28] ^ x0, wkey[29] ^ x1, wkey[30] ^ x2, wkey[31] ^ x3); lt();
        sb0(wkey[32] ^ x0, wkey[33] ^ x1, wkey[34] ^ x2, wkey[35] ^ x3); lt();
        sb1(wkey[36] ^ x0, wkey[37] ^ x1, wkey[38] ^ x2, wkey[39] ^ x3); lt();
        sb2(wkey[40] ^ x0, wkey[41] ^ x1, wkey[42] ^ x2, wkey[43] ^ x3); lt();
        sb3(wkey[44] ^ x0, wkey[45] ^ x1, wkey[46] ^ x2, wkey[47] ^ x3); lt();
        sb4(wkey[48] ^ x0, wkey[49] ^ x1, wkey[50] ^ x2, wkey[51] ^ x3); lt();
        sb5(wkey[52] ^ x0, wkey[53] ^ x1, wkey[54] ^ x2, wkey[55] ^ x3); lt();
        sb6(wkey[56] ^ x0, wkey[57] ^ x1, wkey[58] ^ x2, wkey[59] ^ x3); lt();
        sb7(wkey[60] ^ x0, wkey[61] ^ x1, wkey[62] ^ x2, wkey[63] ^ x3); lt();
        sb0(wkey[64] ^ x0, wkey[65] ^ x1, wkey[66] ^ x2, wkey[67] ^ x3); lt();
        sb1(wkey[68] ^ x0, wkey[69] ^ x1, wkey[70] ^ x2, wkey[71] ^ x3); lt();
        sb2(wkey[72] ^ x0, wkey[73] ^ x1, wkey[74] ^ x2, wkey[75] ^ x3); lt();
        sb3(wkey[76] ^ x0, wkey[77] ^ x1, wkey[78] ^ x2, wkey[79] ^ x3); lt();
        sb4(wkey[80] ^ x0, wkey[81] ^ x1, wkey[82] ^ x2, wkey[83] ^ x3); lt();
        sb5(wkey[84] ^ x0, wkey[85] ^ x1, wkey[86] ^ x2, wkey[87] ^ x3); lt();
        sb6(wkey[88] ^ x0, wkey[89] ^ x1, wkey[90] ^ x2, wkey[91] ^ x3); lt();
        sb7(wkey[92] ^ x0, wkey[93] ^ x1, wkey[94] ^ x2, wkey[95] ^ x3); lt();
        sb0(wkey[96] ^ x0, wkey[97] ^ x1, wkey[98] ^ x2, wkey[99] ^ x3); lt();
        sb1(wkey[100] ^ x0, wkey[101] ^ x1, wkey[102] ^ x2, wkey[103] ^ x3); lt();
        sb2(wkey[104] ^ x0, wkey[105] ^ x1, wkey[106] ^ x2, wkey[107] ^ x3); lt();
        sb3(wkey[108] ^ x0, wkey[109] ^ x1, wkey[110] ^ x2, wkey[111] ^ x3); lt();
        sb4(wkey[112] ^ x0, wkey[113] ^ x1, wkey[114] ^ x2, wkey[115] ^ x3); lt();
        sb5(wkey[116] ^ x0, wkey[117] ^ x1, wkey[118] ^ x2, wkey[119] ^ x3); lt();
        sb6(wkey[120] ^ x0, wkey[121] ^ x1, wkey[122] ^ x2, wkey[123] ^ x3); lt();
        sb7(wkey[124] ^ x0, wkey[125] ^ x1, wkey[126] ^ x2, wkey[127] ^ x3);

        wordtobytes(wkey[131] ^ x3, out, outoff);
        wordtobytes(wkey[130] ^ x2, out, outoff + 4);
        wordtobytes(wkey[129] ^ x1, out, outoff + 8);
        wordtobytes(wkey[128] ^ x0, out, outoff + 12);
    }

    /**
     * decrypt one block of ciphertext.
     *
     * @param in the array containing the input data.
     * @param inoff offset into the in array the data starts at.
     * @param out the array the output data will be copied into.
     * @param outoff the offset into the out array the output will start at.
     */
    private void decryptblock(
        byte[]  in,
        int     inoff,
        byte[]  out,
        int     outoff)
    {
        x3 = wkey[131] ^ bytestoword(in, inoff);
        x2 = wkey[130] ^ bytestoword(in, inoff + 4);
        x1 = wkey[129] ^ bytestoword(in, inoff + 8);
        x0 = wkey[128] ^ bytestoword(in, inoff + 12);

        ib7(x0, x1, x2, x3);
        x0 ^= wkey[124]; x1 ^= wkey[125]; x2 ^= wkey[126]; x3 ^= wkey[127];
        inverselt(); ib6(x0, x1, x2, x3);
        x0 ^= wkey[120]; x1 ^= wkey[121]; x2 ^= wkey[122]; x3 ^= wkey[123];
        inverselt(); ib5(x0, x1, x2, x3);
        x0 ^= wkey[116]; x1 ^= wkey[117]; x2 ^= wkey[118]; x3 ^= wkey[119];
        inverselt(); ib4(x0, x1, x2, x3);
        x0 ^= wkey[112]; x1 ^= wkey[113]; x2 ^= wkey[114]; x3 ^= wkey[115];
        inverselt(); ib3(x0, x1, x2, x3);
        x0 ^= wkey[108]; x1 ^= wkey[109]; x2 ^= wkey[110]; x3 ^= wkey[111];
        inverselt(); ib2(x0, x1, x2, x3);
        x0 ^= wkey[104]; x1 ^= wkey[105]; x2 ^= wkey[106]; x3 ^= wkey[107];
        inverselt(); ib1(x0, x1, x2, x3);
        x0 ^= wkey[100]; x1 ^= wkey[101]; x2 ^= wkey[102]; x3 ^= wkey[103];
        inverselt(); ib0(x0, x1, x2, x3);
        x0 ^= wkey[96]; x1 ^= wkey[97]; x2 ^= wkey[98]; x3 ^= wkey[99];
        inverselt(); ib7(x0, x1, x2, x3);
        x0 ^= wkey[92]; x1 ^= wkey[93]; x2 ^= wkey[94]; x3 ^= wkey[95];
        inverselt(); ib6(x0, x1, x2, x3);
        x0 ^= wkey[88]; x1 ^= wkey[89]; x2 ^= wkey[90]; x3 ^= wkey[91];
        inverselt(); ib5(x0, x1, x2, x3);
        x0 ^= wkey[84]; x1 ^= wkey[85]; x2 ^= wkey[86]; x3 ^= wkey[87];
        inverselt(); ib4(x0, x1, x2, x3);
        x0 ^= wkey[80]; x1 ^= wkey[81]; x2 ^= wkey[82]; x3 ^= wkey[83];
        inverselt(); ib3(x0, x1, x2, x3);
        x0 ^= wkey[76]; x1 ^= wkey[77]; x2 ^= wkey[78]; x3 ^= wkey[79];
        inverselt(); ib2(x0, x1, x2, x3);
        x0 ^= wkey[72]; x1 ^= wkey[73]; x2 ^= wkey[74]; x3 ^= wkey[75];
        inverselt(); ib1(x0, x1, x2, x3);
        x0 ^= wkey[68]; x1 ^= wkey[69]; x2 ^= wkey[70]; x3 ^= wkey[71];
        inverselt(); ib0(x0, x1, x2, x3);
        x0 ^= wkey[64]; x1 ^= wkey[65]; x2 ^= wkey[66]; x3 ^= wkey[67];
        inverselt(); ib7(x0, x1, x2, x3);
        x0 ^= wkey[60]; x1 ^= wkey[61]; x2 ^= wkey[62]; x3 ^= wkey[63];
        inverselt(); ib6(x0, x1, x2, x3);
        x0 ^= wkey[56]; x1 ^= wkey[57]; x2 ^= wkey[58]; x3 ^= wkey[59];
        inverselt(); ib5(x0, x1, x2, x3);
        x0 ^= wkey[52]; x1 ^= wkey[53]; x2 ^= wkey[54]; x3 ^= wkey[55];
        inverselt(); ib4(x0, x1, x2, x3);
        x0 ^= wkey[48]; x1 ^= wkey[49]; x2 ^= wkey[50]; x3 ^= wkey[51];
        inverselt(); ib3(x0, x1, x2, x3);
        x0 ^= wkey[44]; x1 ^= wkey[45]; x2 ^= wkey[46]; x3 ^= wkey[47];
        inverselt(); ib2(x0, x1, x2, x3);
        x0 ^= wkey[40]; x1 ^= wkey[41]; x2 ^= wkey[42]; x3 ^= wkey[43];
        inverselt(); ib1(x0, x1, x2, x3);
        x0 ^= wkey[36]; x1 ^= wkey[37]; x2 ^= wkey[38]; x3 ^= wkey[39];
        inverselt(); ib0(x0, x1, x2, x3);
        x0 ^= wkey[32]; x1 ^= wkey[33]; x2 ^= wkey[34]; x3 ^= wkey[35];
        inverselt(); ib7(x0, x1, x2, x3);
        x0 ^= wkey[28]; x1 ^= wkey[29]; x2 ^= wkey[30]; x3 ^= wkey[31];
        inverselt(); ib6(x0, x1, x2, x3);
        x0 ^= wkey[24]; x1 ^= wkey[25]; x2 ^= wkey[26]; x3 ^= wkey[27];
        inverselt(); ib5(x0, x1, x2, x3);
        x0 ^= wkey[20]; x1 ^= wkey[21]; x2 ^= wkey[22]; x3 ^= wkey[23];
        inverselt(); ib4(x0, x1, x2, x3);
        x0 ^= wkey[16]; x1 ^= wkey[17]; x2 ^= wkey[18]; x3 ^= wkey[19];
        inverselt(); ib3(x0, x1, x2, x3);
        x0 ^= wkey[12]; x1 ^= wkey[13]; x2 ^= wkey[14]; x3 ^= wkey[15];
        inverselt(); ib2(x0, x1, x2, x3);
        x0 ^= wkey[8]; x1 ^= wkey[9]; x2 ^= wkey[10]; x3 ^= wkey[11];
        inverselt(); ib1(x0, x1, x2, x3);
        x0 ^= wkey[4]; x1 ^= wkey[5]; x2 ^= wkey[6]; x3 ^= wkey[7];
        inverselt(); ib0(x0, x1, x2, x3);

        wordtobytes(x3 ^ wkey[3], out, outoff);
        wordtobytes(x2 ^ wkey[2], out, outoff + 4);
        wordtobytes(x1 ^ wkey[1], out, outoff + 8);
        wordtobytes(x0 ^ wkey[0], out, outoff + 12);
    }

    /**
     * the sboxes below are based on the work of brian gladman and
     * sam simpson, whose original notice appears below.
     * <p>
     * for further details see:
     *      http://fp.gladman.plus.com/cryptography_technology/serpent/
     */

    /* partially optimised serpent s box boolean functions derived  */
    /* using a recursive descent analyser but without a full search */
    /* of all subtrees. this set of s boxes is the result of work    */
    /* by sam simpson and brian gladman using the spare time on a    */
    /* cluster of high capacity servers to search for s boxes with    */
    /* this customised search engine. there are now an average of    */
    /* 15.375 terms    per s box.                                        */
    /*                                                              */
    /* copyright:   dr b. r gladman (gladman@seven77.demon.co.uk)   */
    /*                and sam simpson (s.simpson@mia.co.uk)            */
    /*              17th december 1998                                */
    /*                                                              */
    /* we hereby give permission for information in this file to be */
    /* used freely subject only to acknowledgement of its origin.    */

    /**
     * s0 - { 3, 8,15, 1,10, 6, 5,11,14,13, 4, 2, 7, 0, 9,12 } - 15 terms.
     */
    private void sb0(int a, int b, int c, int d)    
    {
        int    t1 = a ^ d;        
        int    t3 = c ^ t1;    
        int    t4 = b ^ t3;    
        x3 = (a & d) ^ t4;    
        int    t7 = a ^ (b & t1);    
        x2 = t4 ^ (c | t7);    
        int    t12 = x3 & (t3 ^ t7);    
        x1 = (~t3) ^ t12;    
        x0 = t12 ^ (~t7);
    }

    /**
     * invso - {13, 3,11, 0,10, 6, 5,12, 1,14, 4, 7,15, 9, 8, 2 } - 15 terms.
     */
    private void ib0(int a, int b, int c, int d)    
    {
        int    t1 = ~a;        
        int    t2 = a ^ b;        
        int    t4 = d ^ (t1 | t2);    
        int    t5 = c ^ t4;    
        x2 = t2 ^ t5;    
        int    t8 = t1 ^ (d & t2);    
        x1 = t4 ^ (x2 & t8);    
        x3 = (a & t4) ^ (t5 | x1);    
        x0 = x3 ^ (t5 ^ t8);
    }

    /**
     * s1 - {15,12, 2, 7, 9, 0, 5,10, 1,11,14, 8, 6,13, 3, 4 } - 14 terms.
     */
    private void sb1(int a, int b, int c, int d)    
    {
        int    t2 = b ^ (~a);    
        int    t5 = c ^ (a | t2);    
        x2 = d ^ t5;        
        int    t7 = b ^ (d | t2);    
        int    t8 = t2 ^ x2;    
        x3 = t8 ^ (t5 & t7);    
        int    t11 = t5 ^ t7;    
        x1 = x3 ^ t11;    
        x0 = t5 ^ (t8 & t11);
    }

    /**
     * invs1 - { 5, 8, 2,14,15, 6,12, 3,11, 4, 7, 9, 1,13,10, 0 } - 14 steps.
     */
    private void ib1(int a, int b, int c, int d)    
    {
        int    t1 = b ^ d;        
        int    t3 = a ^ (b & t1);    
        int    t4 = t1 ^ t3;    
        x3 = c ^ t4;        
        int    t7 = b ^ (t1 & t3);    
        int    t8 = x3 | t7;    
        x1 = t3 ^ t8;    
        int    t10 = ~x1;        
        int    t11 = x3 ^ t7;    
        x0 = t10 ^ t11;    
        x2 = t4 ^ (t10 | t11);
    }

    /**
     * s2 - { 8, 6, 7, 9, 3,12,10,15,13, 1,14, 4, 0,11, 5, 2 } - 16 terms.
     */
    private void sb2(int a, int b, int c, int d)    
    {
        int    t1 = ~a;        
        int    t2 = b ^ d;
        int    t3 = c & t1;
        x0 = t2 ^ t3;
        int    t5 = c ^ t1;
        int    t6 = c ^ x0;
        int    t7 = b & t6;
        x3 = t5 ^ t7;
        x2 = a ^ ((d | t7) & (x0 | t5));
        x1 = (t2 ^ x3) ^ (x2 ^ (d | t1));
    }

    /**
     * invs2 - {12, 9,15, 4,11,14, 1, 2, 0, 3, 6,13, 5, 8,10, 7 } - 16 steps.
     */
    private void ib2(int a, int b, int c, int d)    
    {
        int    t1 = b ^ d;        
        int    t2 = ~t1;        
        int    t3 = a ^ c;
        int    t4 = c ^ t1;
        int    t5 = b & t4;
        x0 = t3 ^ t5;
        int    t7 = a | t2;
        int    t8 = d ^ t7;
        int    t9 = t3 | t8;
        x3 = t1 ^ t9;
        int    t11 = ~t4;        
        int    t12 = x0 | x3;
        x1 = t11 ^ t12;
        x2 = (d & t11) ^ (t3 ^ t12);
    }

    /**
     * s3 - { 0,15,11, 8,12, 9, 6, 3,13, 1, 2, 4,10, 7, 5,14 } - 16 terms.
     */
    private void sb3(int a, int b, int c, int d)    
    {
        int    t1 = a ^ b;        
        int    t2 = a & c;        
        int    t3 = a | d;        
        int    t4 = c ^ d;        
        int    t5 = t1 & t3;    
        int    t6 = t2 | t5;    
        x2 = t4 ^ t6;    
        int    t8 = b ^ t3;    
        int    t9 = t6 ^ t8;    
        int    t10 = t4 & t9;    
        x0 = t1 ^ t10;    
        int    t12 = x2 & x0;    
        x1 = t9 ^ t12;    
        x3 = (b | d) ^ (t4 ^ t12);
    }

    /**
     * invs3 - { 0, 9,10, 7,11,14, 6,13, 3, 5,12, 2, 4, 8,15, 1 } - 15 terms
     */
    private void ib3(int a, int b, int c, int d)    
    {
        int    t1 = a | b;        
        int    t2 = b ^ c;        
        int    t3 = b & t2;    
        int    t4 = a ^ t3;    
        int    t5 = c ^ t4;    
        int    t6 = d | t4;    
        x0 = t2 ^ t6;    
        int    t8 = t2 | t6;    
        int    t9 = d ^ t8;    
        x2 = t5 ^ t9;    
        int    t11 = t1 ^ t9;    
        int    t12 = x0 & t11;    
        x3 = t4 ^ t12;    
        x1 = x3 ^ (x0 ^ t11);
    }

    /**
     * s4 - { 1,15, 8, 3,12, 0,11, 6, 2, 5, 4,10, 9,14, 7,13 } - 15 terms.
     */
    private void sb4(int a, int b, int c, int d)    
    {
        int    t1 = a ^ d;        
        int    t2 = d & t1;    
        int    t3 = c ^ t2;    
        int    t4 = b | t3;    
        x3 = t1 ^ t4;    
        int    t6 = ~b;        
        int    t7 = t1 | t6;    
        x0 = t3 ^ t7;    
        int    t9 = a & x0;        
        int    t10 = t1 ^ t6;    
        int    t11 = t4 & t10;    
        x2 = t9 ^ t11;    
        x1 = (a ^ t3) ^ (t10 & x2);
    }

    /**
     * invs4 - { 5, 0, 8, 3,10, 9, 7,14, 2,12,11, 6, 4,15,13, 1 } - 15 terms.
     */
    private void ib4(int a, int b, int c, int d)    
    {
        int    t1 = c | d;        
        int    t2 = a & t1;    
        int    t3 = b ^ t2;    
        int    t4 = a & t3;    
        int    t5 = c ^ t4;    
        x1 = d ^ t5;        
        int    t7 = ~a;        
        int    t8 = t5 & x1;    
        x3 = t3 ^ t8;    
        int    t10 = x1 | t7;    
        int    t11 = d ^ t10;    
        x0 = x3 ^ t11;    
        x2 = (t3 & t11) ^ (x1 ^ t7);
    }

    /**
     * s5 - {15, 5, 2,11, 4,10, 9,12, 0, 3,14, 8,13, 6, 7, 1 } - 16 terms.
     */
    private void sb5(int a, int b, int c, int d)    
    {
        int    t1 = ~a;        
        int    t2 = a ^ b;        
        int    t3 = a ^ d;        
        int    t4 = c ^ t1;    
        int    t5 = t2 | t3;    
        x0 = t4 ^ t5;    
        int    t7 = d & x0;        
        int    t8 = t2 ^ x0;    
        x1 = t7 ^ t8;    
        int    t10 = t1 | x0;    
        int    t11 = t2 | t7;    
        int    t12 = t3 ^ t10;    
        x2 = t11 ^ t12;    
        x3 = (b ^ t7) ^ (x1 & t12);
    }

    /**
     * invs5 - { 8,15, 2, 9, 4, 1,13,14,11, 6, 5, 3, 7,12,10, 0 } - 16 terms.
     */
    private void ib5(int a, int b, int c, int d)    
    {
        int    t1 = ~c;
        int    t2 = b & t1;
        int    t3 = d ^ t2;
        int    t4 = a & t3;
        int    t5 = b ^ t1;
        x3 = t4 ^ t5;
        int    t7 = b | x3;
        int    t8 = a & t7;
        x1 = t3 ^ t8;
        int    t10 = a | d;
        int    t11 = t1 ^ t7;
        x0 = t10 ^ t11;
        x2 = (b & t10) ^ (t4 | (a ^ c));
    }

    /**
     * s6 - { 7, 2,12, 5, 8, 4, 6,11,14, 9, 1,15,13, 3,10, 0 } - 15 terms.
     */
    private void sb6(int a, int b, int c, int d)    
    {
        int    t1 = ~a;        
        int    t2 = a ^ d;        
        int    t3 = b ^ t2;    
        int    t4 = t1 | t2;    
        int    t5 = c ^ t4;    
        x1 = b ^ t5;        
        int    t7 = t2 | x1;    
        int    t8 = d ^ t7;    
        int    t9 = t5 & t8;    
        x2 = t3 ^ t9;    
        int    t11 = t5 ^ t8;    
        x0 = x2 ^ t11;    
        x3 = (~t5) ^ (t3 & t11);
    }

    /**
     * invs6 - {15,10, 1,13, 5, 3, 6, 0, 4, 9,14, 7, 2,12, 8,11 } - 15 terms.
     */
    private void ib6(int a, int b, int c, int d)    
    {
        int    t1 = ~a;        
        int    t2 = a ^ b;        
        int    t3 = c ^ t2;    
        int    t4 = c | t1;    
        int    t5 = d ^ t4;    
        x1 = t3 ^ t5;    
        int    t7 = t3 & t5;    
        int    t8 = t2 ^ t7;    
        int    t9 = b | t8;    
        x3 = t5 ^ t9;    
        int    t11 = b | x3;    
        x0 = t8 ^ t11;    
        x2 = (d & t1) ^ (t3 ^ t11);
    }

    /**
     * s7 - { 1,13,15, 0,14, 8, 2,11, 7, 4,12,10, 9, 3, 5, 6 } - 16 terms.
     */
    private void sb7(int a, int b, int c, int d)    
    {
        int    t1 = b ^ c;        
        int    t2 = c & t1;    
        int    t3 = d ^ t2;    
        int    t4 = a ^ t3;    
        int    t5 = d | t1;    
        int    t6 = t4 & t5;    
        x1 = b ^ t6;        
        int    t8 = t3 | x1;    
        int    t9 = a & t4;    
        x3 = t1 ^ t9;    
        int    t11 = t4 ^ t8;    
        int    t12 = x3 & t11;    
        x2 = t3 ^ t12;    
        x0 = (~t11) ^ (x3 & x2);
    }

    /**
     * invs7 - { 3, 0, 6,13, 9,14,15, 8, 5,12,11, 7,10, 1, 4, 2 } - 17 terms.
     */
    private void ib7(int a, int b, int c, int d)    
    {
        int t3 = c | (a & b);
        int    t4 = d & (a | b);
        x3 = t3 ^ t4;
        int    t6 = ~d;
        int    t7 = b ^ t4;
        int    t9 = t7 | (x3 ^ t6);
        x1 = a ^ t9;
        x0 = (c ^ t7) ^ (d | x1);
        x2 = (t3 ^ x1) ^ (x0 ^ (a & x3));
    }

    /**
     * apply the linear transformation to the register set.
     */
    private void lt()
    {
        int x0  = rotateleft(x0, 13);
        int x2  = rotateleft(x2, 3);
        int x1  = x1 ^ x0 ^ x2 ;
        int x3  = x3 ^ x2 ^ x0 << 3;

        x1  = rotateleft(x1, 1);
        x3  = rotateleft(x3, 7);
        x0  = rotateleft(x0 ^ x1 ^ x3, 5);
        x2  = rotateleft(x2 ^ x3 ^ (x1 << 7), 22);
    }

    /**
     * apply the inverse of the linear transformation to the register set.
     */
    private void inverselt()
    {
        int x2 = rotateright(x2, 22) ^ x3 ^ (x1 << 7);
        int x0 = rotateright(x0, 5) ^ x1 ^ x3;
        int x3 = rotateright(x3, 7);
        int x1 = rotateright(x1, 1);
        x3 = x3 ^ x2 ^ x0 << 3;
        x1 = x1 ^ x0 ^ x2;
        x2 = rotateright(x2, 3);
        x0 = rotateright(x0, 13);
    }
}
