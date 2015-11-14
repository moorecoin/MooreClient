package org.ripple.bouncycastle.crypto.engines;

import org.ripple.bouncycastle.crypto.blockcipher;
import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.datalengthexception;
import org.ripple.bouncycastle.crypto.outputlengthexception;
import org.ripple.bouncycastle.crypto.params.keyparameter;

/**
 * an implementation of the aes (rijndael), from fips-197.
 * <p>
 * for further details see: <a href="http://csrc.nist.gov/encryption/aes/">http://csrc.nist.gov/encryption/aes/</a>.
 *
 * this implementation is based on optimizations from dr. brian gladman's paper and c code at
 * <a href="http://fp.gladman.plus.com/cryptography_technology/rijndael/">http://fp.gladman.plus.com/cryptography_technology/rijndael/</a>
 *
 * there are three levels of tradeoff of speed vs memory
 * because java has no preprocessor, they are written as three separate classes from which to choose
 *
 * the fastest uses 8kbytes of static tables to precompute round calculations, 4 256 word tables for encryption
 * and 4 for decryption.
 *
 * the middle performance version uses only one 256 word table for each, for a total of 2kbytes,
 * adding 12 rotate operations per round to compute the values contained in the other tables from
 * the contents of the first
 *
 * the slowest version uses no static tables at all and computes the values
 * in each round.
 * <p>
 * this file contains the slowest performance version with no static tables
 * for round precomputation, but it has the smallest foot print.
 *
 */
public class aeslightengine
    implements blockcipher
{
    // the s box
    private static final byte[] s = {
        (byte)99, (byte)124, (byte)119, (byte)123, (byte)242, (byte)107, (byte)111, (byte)197,
        (byte)48,   (byte)1, (byte)103,  (byte)43, (byte)254, (byte)215, (byte)171, (byte)118,
        (byte)202, (byte)130, (byte)201, (byte)125, (byte)250,  (byte)89,  (byte)71, (byte)240,
        (byte)173, (byte)212, (byte)162, (byte)175, (byte)156, (byte)164, (byte)114, (byte)192,
        (byte)183, (byte)253, (byte)147,  (byte)38,  (byte)54,  (byte)63, (byte)247, (byte)204,
        (byte)52, (byte)165, (byte)229, (byte)241, (byte)113, (byte)216,  (byte)49,  (byte)21,
        (byte)4, (byte)199,  (byte)35, (byte)195,  (byte)24, (byte)150,   (byte)5, (byte)154,
        (byte)7,  (byte)18, (byte)128, (byte)226, (byte)235,  (byte)39, (byte)178, (byte)117,
        (byte)9, (byte)131,  (byte)44,  (byte)26,  (byte)27, (byte)110,  (byte)90, (byte)160,
        (byte)82,  (byte)59, (byte)214, (byte)179,  (byte)41, (byte)227,  (byte)47, (byte)132,
        (byte)83, (byte)209,   (byte)0, (byte)237,  (byte)32, (byte)252, (byte)177,  (byte)91,
        (byte)106, (byte)203, (byte)190,  (byte)57,  (byte)74,  (byte)76,  (byte)88, (byte)207,
        (byte)208, (byte)239, (byte)170, (byte)251,  (byte)67,  (byte)77,  (byte)51, (byte)133,
        (byte)69, (byte)249,   (byte)2, (byte)127,  (byte)80,  (byte)60, (byte)159, (byte)168,
        (byte)81, (byte)163,  (byte)64, (byte)143, (byte)146, (byte)157,  (byte)56, (byte)245,
        (byte)188, (byte)182, (byte)218,  (byte)33,  (byte)16, (byte)255, (byte)243, (byte)210,
        (byte)205,  (byte)12,  (byte)19, (byte)236,  (byte)95, (byte)151,  (byte)68,  (byte)23,
        (byte)196, (byte)167, (byte)126,  (byte)61, (byte)100,  (byte)93,  (byte)25, (byte)115,
        (byte)96, (byte)129,  (byte)79, (byte)220,  (byte)34,  (byte)42, (byte)144, (byte)136,
        (byte)70, (byte)238, (byte)184,  (byte)20, (byte)222,  (byte)94,  (byte)11, (byte)219,
        (byte)224,  (byte)50,  (byte)58,  (byte)10,  (byte)73,   (byte)6,  (byte)36,  (byte)92,
        (byte)194, (byte)211, (byte)172,  (byte)98, (byte)145, (byte)149, (byte)228, (byte)121,
        (byte)231, (byte)200,  (byte)55, (byte)109, (byte)141, (byte)213,  (byte)78, (byte)169,
        (byte)108,  (byte)86, (byte)244, (byte)234, (byte)101, (byte)122, (byte)174,   (byte)8,
        (byte)186, (byte)120,  (byte)37,  (byte)46,  (byte)28, (byte)166, (byte)180, (byte)198,
        (byte)232, (byte)221, (byte)116,  (byte)31,  (byte)75, (byte)189, (byte)139, (byte)138,
        (byte)112,  (byte)62, (byte)181, (byte)102,  (byte)72,   (byte)3, (byte)246,  (byte)14,
        (byte)97,  (byte)53,  (byte)87, (byte)185, (byte)134, (byte)193,  (byte)29, (byte)158,
        (byte)225, (byte)248, (byte)152,  (byte)17, (byte)105, (byte)217, (byte)142, (byte)148,
        (byte)155,  (byte)30, (byte)135, (byte)233, (byte)206,  (byte)85,  (byte)40, (byte)223,
        (byte)140, (byte)161, (byte)137,  (byte)13, (byte)191, (byte)230,  (byte)66, (byte)104,
        (byte)65, (byte)153,  (byte)45,  (byte)15, (byte)176,  (byte)84, (byte)187,  (byte)22,
    };

    // the inverse s-box
    private static final byte[] si = {
        (byte)82,   (byte)9, (byte)106, (byte)213,  (byte)48,  (byte)54, (byte)165,  (byte)56,
        (byte)191,  (byte)64, (byte)163, (byte)158, (byte)129, (byte)243, (byte)215, (byte)251,
        (byte)124, (byte)227,  (byte)57, (byte)130, (byte)155,  (byte)47, (byte)255, (byte)135,
        (byte)52, (byte)142,  (byte)67,  (byte)68, (byte)196, (byte)222, (byte)233, (byte)203,
        (byte)84, (byte)123, (byte)148,  (byte)50, (byte)166, (byte)194,  (byte)35,  (byte)61,
        (byte)238,  (byte)76, (byte)149,  (byte)11,  (byte)66, (byte)250, (byte)195,  (byte)78,
        (byte)8,  (byte)46, (byte)161, (byte)102,  (byte)40, (byte)217,  (byte)36, (byte)178,
        (byte)118,  (byte)91, (byte)162,  (byte)73, (byte)109, (byte)139, (byte)209,  (byte)37,
        (byte)114, (byte)248, (byte)246, (byte)100, (byte)134, (byte)104, (byte)152,  (byte)22,
        (byte)212, (byte)164,  (byte)92, (byte)204,  (byte)93, (byte)101, (byte)182, (byte)146,
        (byte)108, (byte)112,  (byte)72,  (byte)80, (byte)253, (byte)237, (byte)185, (byte)218,
        (byte)94,  (byte)21,  (byte)70,  (byte)87, (byte)167, (byte)141, (byte)157, (byte)132,
        (byte)144, (byte)216, (byte)171,   (byte)0, (byte)140, (byte)188, (byte)211,  (byte)10,
        (byte)247, (byte)228,  (byte)88,   (byte)5, (byte)184, (byte)179,  (byte)69,   (byte)6,
        (byte)208,  (byte)44,  (byte)30, (byte)143, (byte)202,  (byte)63,  (byte)15,   (byte)2,
        (byte)193, (byte)175, (byte)189,   (byte)3,   (byte)1,  (byte)19, (byte)138, (byte)107,
        (byte)58, (byte)145,  (byte)17,  (byte)65,  (byte)79, (byte)103, (byte)220, (byte)234,
        (byte)151, (byte)242, (byte)207, (byte)206, (byte)240, (byte)180, (byte)230, (byte)115,
        (byte)150, (byte)172, (byte)116,  (byte)34, (byte)231, (byte)173,  (byte)53, (byte)133,
        (byte)226, (byte)249,  (byte)55, (byte)232,  (byte)28, (byte)117, (byte)223, (byte)110,
        (byte)71, (byte)241,  (byte)26, (byte)113,  (byte)29,  (byte)41, (byte)197, (byte)137,
        (byte)111, (byte)183,  (byte)98,  (byte)14, (byte)170,  (byte)24, (byte)190,  (byte)27,
        (byte)252,  (byte)86,  (byte)62,  (byte)75, (byte)198, (byte)210, (byte)121,  (byte)32,
        (byte)154, (byte)219, (byte)192, (byte)254, (byte)120, (byte)205,  (byte)90, (byte)244,
        (byte)31, (byte)221, (byte)168,  (byte)51, (byte)136,   (byte)7, (byte)199,  (byte)49,
        (byte)177,  (byte)18,  (byte)16,  (byte)89,  (byte)39, (byte)128, (byte)236,  (byte)95,
        (byte)96,  (byte)81, (byte)127, (byte)169,  (byte)25, (byte)181,  (byte)74,  (byte)13,
        (byte)45, (byte)229, (byte)122, (byte)159, (byte)147, (byte)201, (byte)156, (byte)239,
        (byte)160, (byte)224,  (byte)59,  (byte)77, (byte)174,  (byte)42, (byte)245, (byte)176,
        (byte)200, (byte)235, (byte)187,  (byte)60, (byte)131,  (byte)83, (byte)153,  (byte)97,
        (byte)23,  (byte)43,   (byte)4, (byte)126, (byte)186, (byte)119, (byte)214,  (byte)38,
        (byte)225, (byte)105,  (byte)20,  (byte)99,  (byte)85,  (byte)33,  (byte)12, (byte)125,
        };

    // vector used in calculating key schedule (powers of x in gf(256))
    private static final int[] rcon = {
         0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
         0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91 };

    private static int shift(int r, int shift)
    {
        return (r >>> shift) | (r << -shift);
    }

    /* multiply four bytes in gf(2^8) by 'x' {02} in parallel */

    private static final int m1 = 0x80808080;
    private static final int m2 = 0x7f7f7f7f;
    private static final int m3 = 0x0000001b;

    private static int ffmulx(int x)
    {
        return (((x & m2) << 1) ^ (((x & m1) >>> 7) * m3));
    }

    /* 
       the following defines provide alternative definitions of ffmulx that might
       give improved performance if a fast 32-bit multiply is not available.
       
       private int ffmulx(int x) { int u = x & m1; u |= (u >> 1); return ((x & m2) << 1) ^ ((u >>> 3) | (u >>> 6)); } 
       private static final int  m4 = 0x1b1b1b1b;
       private int ffmulx(int x) { int u = x & m1; return ((x & m2) << 1) ^ ((u - (u >>> 7)) & m4); } 

    */

    private static int mcol(int x)
    {
        int f2 = ffmulx(x);
        return f2 ^ shift(x ^ f2, 8) ^ shift(x, 16) ^ shift(x, 24);
    }

    private static int inv_mcol(int x)
    {
        int f2 = ffmulx(x);
        int f4 = ffmulx(f2);
        int f8 = ffmulx(f4);
        int f9 = x ^ f8;
        
        return f2 ^ f4 ^ f8 ^ shift(f2 ^ f9, 8) ^ shift(f4 ^ f9, 16) ^ shift(f9, 24);
    }


    private static int subword(int x)
    {
        return (s[x&255]&255 | ((s[(x>>8)&255]&255)<<8) | ((s[(x>>16)&255]&255)<<16) | s[(x>>24)&255]<<24);
    }

    /**
     * calculate the necessary round keys
     * the number of calculations depends on key size and block size
     * aes specified a fixed block size of 128 bits and key sizes 128/192/256 bits
     * this code is written assuming those are the only possible values
     */
    private int[][] generateworkingkey(
                                    byte[] key,
                                    boolean forencryption)
    {
        int         kc = key.length / 4;  // key length in words
        int         t;
        
        if (((kc != 4) && (kc != 6) && (kc != 8)) || ((kc * 4) != key.length))
        {
            throw new illegalargumentexception("key length not 128/192/256 bits.");
        }

        rounds = kc + 6;  // this is not always true for the generalized rijndael that allows larger block sizes
        int[][] w = new int[rounds+1][4];   // 4 words in a block
        
        //
        // copy the key into the round key array
        //
        
        t = 0;
        int i = 0;
        while (i < key.length)
            {
                w[t >> 2][t & 3] = (key[i]&0xff) | ((key[i+1]&0xff) << 8) | ((key[i+2]&0xff) << 16) | (key[i+3] << 24);
                i+=4;
                t++;
            }
        
        //
        // while not enough round key material calculated
        // calculate new values
        //
        int k = (rounds + 1) << 2;
        for (i = kc; (i < k); i++)
            {
                int temp = w[(i-1)>>2][(i-1)&3];
                if ((i % kc) == 0)
                {
                    temp = subword(shift(temp, 8)) ^ rcon[(i / kc)-1];
                }
                else if ((kc > 6) && ((i % kc) == 4))
                {
                    temp = subword(temp);
                }
                
                w[i>>2][i&3] = w[(i - kc)>>2][(i-kc)&3] ^ temp;
            }

        if (!forencryption)
        {
            for (int j = 1; j < rounds; j++)
            {
                for (i = 0; i < 4; i++) 
                {
                    w[j][i] = inv_mcol(w[j][i]);
                }
            }
        }

        return w;
    }

    private int         rounds;
    private int[][]     workingkey = null;
    private int         c0, c1, c2, c3;
    private boolean     forencryption;

    private static final int block_size = 16;

    /**
     * default constructor - 128 bit block size.
     */
    public aeslightengine()
    {
    }

    /**
     * initialise an aes cipher.
     *
     * @param forencryption whether or not we are for encryption.
     * @param params the parameters required to set up the cipher.
     * @exception illegalargumentexception if the params argument is
     * inappropriate.
     */
    public void init(
        boolean           forencryption,
        cipherparameters  params)
    {
        if (params instanceof keyparameter)
        {
            workingkey = generateworkingkey(((keyparameter)params).getkey(), forencryption);
            this.forencryption = forencryption;
            return;
        }

        throw new illegalargumentexception("invalid parameter passed to aes init - " + params.getclass().getname());
    }

    public string getalgorithmname()
    {
        return "aes";
    }

    public int getblocksize()
    {
        return block_size;
    }

    public int processblock(
        byte[] in,
        int inoff,
        byte[] out,
        int outoff)
    {
        if (workingkey == null)
        {
            throw new illegalstateexception("aes engine not initialised");
        }

        if ((inoff + (32 / 2)) > in.length)
        {
            throw new datalengthexception("input buffer too short");
        }

        if ((outoff + (32 / 2)) > out.length)
        {
            throw new outputlengthexception("output buffer too short");
        }

        if (forencryption)
        {
            unpackblock(in, inoff);
            encryptblock(workingkey);
            packblock(out, outoff);
        }
        else
        {
            unpackblock(in, inoff);
            decryptblock(workingkey);
            packblock(out, outoff);
        }

        return block_size;
    }

    public void reset()
    {
    }

    private void unpackblock(
        byte[]      bytes,
        int         off)
    {
        int     index = off;

        c0 = (bytes[index++] & 0xff);
        c0 |= (bytes[index++] & 0xff) << 8;
        c0 |= (bytes[index++] & 0xff) << 16;
        c0 |= bytes[index++] << 24;

        c1 = (bytes[index++] & 0xff);
        c1 |= (bytes[index++] & 0xff) << 8;
        c1 |= (bytes[index++] & 0xff) << 16;
        c1 |= bytes[index++] << 24;

        c2 = (bytes[index++] & 0xff);
        c2 |= (bytes[index++] & 0xff) << 8;
        c2 |= (bytes[index++] & 0xff) << 16;
        c2 |= bytes[index++] << 24;

        c3 = (bytes[index++] & 0xff);
        c3 |= (bytes[index++] & 0xff) << 8;
        c3 |= (bytes[index++] & 0xff) << 16;
        c3 |= bytes[index++] << 24;
    }

    private void packblock(
        byte[]      bytes,
        int         off)
    {
        int     index = off;

        bytes[index++] = (byte)c0;
        bytes[index++] = (byte)(c0 >> 8);
        bytes[index++] = (byte)(c0 >> 16);
        bytes[index++] = (byte)(c0 >> 24);

        bytes[index++] = (byte)c1;
        bytes[index++] = (byte)(c1 >> 8);
        bytes[index++] = (byte)(c1 >> 16);
        bytes[index++] = (byte)(c1 >> 24);

        bytes[index++] = (byte)c2;
        bytes[index++] = (byte)(c2 >> 8);
        bytes[index++] = (byte)(c2 >> 16);
        bytes[index++] = (byte)(c2 >> 24);

        bytes[index++] = (byte)c3;
        bytes[index++] = (byte)(c3 >> 8);
        bytes[index++] = (byte)(c3 >> 16);
        bytes[index++] = (byte)(c3 >> 24);
    }

    private void encryptblock(int[][] kw)
    {
        int r, r0, r1, r2, r3;

        c0 ^= kw[0][0];
        c1 ^= kw[0][1];
        c2 ^= kw[0][2];
        c3 ^= kw[0][3];

        for (r = 1; r < rounds - 1;)
        {
            r0 = mcol((s[c0&255]&255) ^ ((s[(c1>>8)&255]&255)<<8) ^ ((s[(c2>>16)&255]&255)<<16) ^ (s[(c3>>24)&255]<<24)) ^ kw[r][0];
            r1 = mcol((s[c1&255]&255) ^ ((s[(c2>>8)&255]&255)<<8) ^ ((s[(c3>>16)&255]&255)<<16) ^ (s[(c0>>24)&255]<<24)) ^ kw[r][1];
            r2 = mcol((s[c2&255]&255) ^ ((s[(c3>>8)&255]&255)<<8) ^ ((s[(c0>>16)&255]&255)<<16) ^ (s[(c1>>24)&255]<<24)) ^ kw[r][2];
            r3 = mcol((s[c3&255]&255) ^ ((s[(c0>>8)&255]&255)<<8) ^ ((s[(c1>>16)&255]&255)<<16) ^ (s[(c2>>24)&255]<<24)) ^ kw[r++][3];
            c0 = mcol((s[r0&255]&255) ^ ((s[(r1>>8)&255]&255)<<8) ^ ((s[(r2>>16)&255]&255)<<16) ^ (s[(r3>>24)&255]<<24)) ^ kw[r][0];
            c1 = mcol((s[r1&255]&255) ^ ((s[(r2>>8)&255]&255)<<8) ^ ((s[(r3>>16)&255]&255)<<16) ^ (s[(r0>>24)&255]<<24)) ^ kw[r][1];
            c2 = mcol((s[r2&255]&255) ^ ((s[(r3>>8)&255]&255)<<8) ^ ((s[(r0>>16)&255]&255)<<16) ^ (s[(r1>>24)&255]<<24)) ^ kw[r][2];
            c3 = mcol((s[r3&255]&255) ^ ((s[(r0>>8)&255]&255)<<8) ^ ((s[(r1>>16)&255]&255)<<16) ^ (s[(r2>>24)&255]<<24)) ^ kw[r++][3];
        }

        r0 = mcol((s[c0&255]&255) ^ ((s[(c1>>8)&255]&255)<<8) ^ ((s[(c2>>16)&255]&255)<<16) ^ (s[(c3>>24)&255]<<24)) ^ kw[r][0];
        r1 = mcol((s[c1&255]&255) ^ ((s[(c2>>8)&255]&255)<<8) ^ ((s[(c3>>16)&255]&255)<<16) ^ (s[(c0>>24)&255]<<24)) ^ kw[r][1];
        r2 = mcol((s[c2&255]&255) ^ ((s[(c3>>8)&255]&255)<<8) ^ ((s[(c0>>16)&255]&255)<<16) ^ (s[(c1>>24)&255]<<24)) ^ kw[r][2];
        r3 = mcol((s[c3&255]&255) ^ ((s[(c0>>8)&255]&255)<<8) ^ ((s[(c1>>16)&255]&255)<<16) ^ (s[(c2>>24)&255]<<24)) ^ kw[r++][3];

        // the final round is a simple function of s

        c0 = (s[r0&255]&255) ^ ((s[(r1>>8)&255]&255)<<8) ^ ((s[(r2>>16)&255]&255)<<16) ^ (s[(r3>>24)&255]<<24) ^ kw[r][0];
        c1 = (s[r1&255]&255) ^ ((s[(r2>>8)&255]&255)<<8) ^ ((s[(r3>>16)&255]&255)<<16) ^ (s[(r0>>24)&255]<<24) ^ kw[r][1];
        c2 = (s[r2&255]&255) ^ ((s[(r3>>8)&255]&255)<<8) ^ ((s[(r0>>16)&255]&255)<<16) ^ (s[(r1>>24)&255]<<24) ^ kw[r][2];
        c3 = (s[r3&255]&255) ^ ((s[(r0>>8)&255]&255)<<8) ^ ((s[(r1>>16)&255]&255)<<16) ^ (s[(r2>>24)&255]<<24) ^ kw[r][3];

    }

    private void decryptblock(int[][] kw)
    {
        int r, r0, r1, r2, r3;

        c0 ^= kw[rounds][0];
        c1 ^= kw[rounds][1];
        c2 ^= kw[rounds][2];
        c3 ^= kw[rounds][3];

        for (r = rounds-1; r>1;)
        {
            r0 = inv_mcol((si[c0&255]&255) ^ ((si[(c3>>8)&255]&255)<<8) ^ ((si[(c2>>16)&255]&255)<<16) ^ (si[(c1>>24)&255]<<24)) ^ kw[r][0];
            r1 = inv_mcol((si[c1&255]&255) ^ ((si[(c0>>8)&255]&255)<<8) ^ ((si[(c3>>16)&255]&255)<<16) ^ (si[(c2>>24)&255]<<24)) ^ kw[r][1];
            r2 = inv_mcol((si[c2&255]&255) ^ ((si[(c1>>8)&255]&255)<<8) ^ ((si[(c0>>16)&255]&255)<<16) ^ (si[(c3>>24)&255]<<24)) ^ kw[r][2];
            r3 = inv_mcol((si[c3&255]&255) ^ ((si[(c2>>8)&255]&255)<<8) ^ ((si[(c1>>16)&255]&255)<<16) ^ (si[(c0>>24)&255]<<24)) ^ kw[r--][3];
            c0 = inv_mcol((si[r0&255]&255) ^ ((si[(r3>>8)&255]&255)<<8) ^ ((si[(r2>>16)&255]&255)<<16) ^ (si[(r1>>24)&255]<<24)) ^ kw[r][0];
            c1 = inv_mcol((si[r1&255]&255) ^ ((si[(r0>>8)&255]&255)<<8) ^ ((si[(r3>>16)&255]&255)<<16) ^ (si[(r2>>24)&255]<<24)) ^ kw[r][1];
            c2 = inv_mcol((si[r2&255]&255) ^ ((si[(r1>>8)&255]&255)<<8) ^ ((si[(r0>>16)&255]&255)<<16) ^ (si[(r3>>24)&255]<<24)) ^ kw[r][2];
            c3 = inv_mcol((si[r3&255]&255) ^ ((si[(r2>>8)&255]&255)<<8) ^ ((si[(r1>>16)&255]&255)<<16) ^ (si[(r0>>24)&255]<<24)) ^ kw[r--][3];
        }

        r0 = inv_mcol((si[c0&255]&255) ^ ((si[(c3>>8)&255]&255)<<8) ^ ((si[(c2>>16)&255]&255)<<16) ^ (si[(c1>>24)&255]<<24)) ^ kw[r][0];
        r1 = inv_mcol((si[c1&255]&255) ^ ((si[(c0>>8)&255]&255)<<8) ^ ((si[(c3>>16)&255]&255)<<16) ^ (si[(c2>>24)&255]<<24)) ^ kw[r][1];
        r2 = inv_mcol((si[c2&255]&255) ^ ((si[(c1>>8)&255]&255)<<8) ^ ((si[(c0>>16)&255]&255)<<16) ^ (si[(c3>>24)&255]<<24)) ^ kw[r][2];
        r3 = inv_mcol((si[c3&255]&255) ^ ((si[(c2>>8)&255]&255)<<8) ^ ((si[(c1>>16)&255]&255)<<16) ^ (si[(c0>>24)&255]<<24)) ^ kw[r][3];

        // the final round's table is a simple function of si

        c0 = (si[r0&255]&255) ^ ((si[(r3>>8)&255]&255)<<8) ^ ((si[(r2>>16)&255]&255)<<16) ^ (si[(r1>>24)&255]<<24) ^ kw[0][0];
        c1 = (si[r1&255]&255) ^ ((si[(r0>>8)&255]&255)<<8) ^ ((si[(r3>>16)&255]&255)<<16) ^ (si[(r2>>24)&255]<<24) ^ kw[0][1];
        c2 = (si[r2&255]&255) ^ ((si[(r1>>8)&255]&255)<<8) ^ ((si[(r0>>16)&255]&255)<<16) ^ (si[(r3>>24)&255]<<24) ^ kw[0][2];
        c3 = (si[r3&255]&255) ^ ((si[(r2>>8)&255]&255)<<8) ^ ((si[(r1>>16)&255]&255)<<16) ^ (si[(r0>>24)&255]<<24) ^ kw[0][3];
    }
}
