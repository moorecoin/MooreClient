package org.ripple.bouncycastle.crypto.engines;

import org.ripple.bouncycastle.crypto.blockcipher;
import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.datalengthexception;
import org.ripple.bouncycastle.crypto.outputlengthexception;
import org.ripple.bouncycastle.crypto.params.keyparameter;

/**
 * a class that provides twofish encryption operations.
 *
 * this java implementation is based on the java reference
 * implementation provided by bruce schneier and developed
 * by raif s. naffah.
 */
public final class twofishengine
    implements blockcipher
{
    private static final byte[][] p =  {
    {  // p0
        (byte) 0xa9, (byte) 0x67, (byte) 0xb3, (byte) 0xe8,
        (byte) 0x04, (byte) 0xfd, (byte) 0xa3, (byte) 0x76,
        (byte) 0x9a, (byte) 0x92, (byte) 0x80, (byte) 0x78,
        (byte) 0xe4, (byte) 0xdd, (byte) 0xd1, (byte) 0x38,
        (byte) 0x0d, (byte) 0xc6, (byte) 0x35, (byte) 0x98,
        (byte) 0x18, (byte) 0xf7, (byte) 0xec, (byte) 0x6c,
        (byte) 0x43, (byte) 0x75, (byte) 0x37, (byte) 0x26,
        (byte) 0xfa, (byte) 0x13, (byte) 0x94, (byte) 0x48,
        (byte) 0xf2, (byte) 0xd0, (byte) 0x8b, (byte) 0x30,
        (byte) 0x84, (byte) 0x54, (byte) 0xdf, (byte) 0x23,
        (byte) 0x19, (byte) 0x5b, (byte) 0x3d, (byte) 0x59,
        (byte) 0xf3, (byte) 0xae, (byte) 0xa2, (byte) 0x82,
        (byte) 0x63, (byte) 0x01, (byte) 0x83, (byte) 0x2e,
        (byte) 0xd9, (byte) 0x51, (byte) 0x9b, (byte) 0x7c,
        (byte) 0xa6, (byte) 0xeb, (byte) 0xa5, (byte) 0xbe,
        (byte) 0x16, (byte) 0x0c, (byte) 0xe3, (byte) 0x61,
        (byte) 0xc0, (byte) 0x8c, (byte) 0x3a, (byte) 0xf5,
        (byte) 0x73, (byte) 0x2c, (byte) 0x25, (byte) 0x0b,
        (byte) 0xbb, (byte) 0x4e, (byte) 0x89, (byte) 0x6b,
        (byte) 0x53, (byte) 0x6a, (byte) 0xb4, (byte) 0xf1,
        (byte) 0xe1, (byte) 0xe6, (byte) 0xbd, (byte) 0x45,
        (byte) 0xe2, (byte) 0xf4, (byte) 0xb6, (byte) 0x66,
        (byte) 0xcc, (byte) 0x95, (byte) 0x03, (byte) 0x56,
        (byte) 0xd4, (byte) 0x1c, (byte) 0x1e, (byte) 0xd7,
        (byte) 0xfb, (byte) 0xc3, (byte) 0x8e, (byte) 0xb5,
        (byte) 0xe9, (byte) 0xcf, (byte) 0xbf, (byte) 0xba,
        (byte) 0xea, (byte) 0x77, (byte) 0x39, (byte) 0xaf,
        (byte) 0x33, (byte) 0xc9, (byte) 0x62, (byte) 0x71,
        (byte) 0x81, (byte) 0x79, (byte) 0x09, (byte) 0xad,
        (byte) 0x24, (byte) 0xcd, (byte) 0xf9, (byte) 0xd8,
        (byte) 0xe5, (byte) 0xc5, (byte) 0xb9, (byte) 0x4d,
        (byte) 0x44, (byte) 0x08, (byte) 0x86, (byte) 0xe7,
        (byte) 0xa1, (byte) 0x1d, (byte) 0xaa, (byte) 0xed,
        (byte) 0x06, (byte) 0x70, (byte) 0xb2, (byte) 0xd2,
        (byte) 0x41, (byte) 0x7b, (byte) 0xa0, (byte) 0x11,
        (byte) 0x31, (byte) 0xc2, (byte) 0x27, (byte) 0x90,
        (byte) 0x20, (byte) 0xf6, (byte) 0x60, (byte) 0xff,
        (byte) 0x96, (byte) 0x5c, (byte) 0xb1, (byte) 0xab,
        (byte) 0x9e, (byte) 0x9c, (byte) 0x52, (byte) 0x1b,
        (byte) 0x5f, (byte) 0x93, (byte) 0x0a, (byte) 0xef,
        (byte) 0x91, (byte) 0x85, (byte) 0x49, (byte) 0xee,
        (byte) 0x2d, (byte) 0x4f, (byte) 0x8f, (byte) 0x3b,
        (byte) 0x47, (byte) 0x87, (byte) 0x6d, (byte) 0x46,
        (byte) 0xd6, (byte) 0x3e, (byte) 0x69, (byte) 0x64,
        (byte) 0x2a, (byte) 0xce, (byte) 0xcb, (byte) 0x2f,
        (byte) 0xfc, (byte) 0x97, (byte) 0x05, (byte) 0x7a,
        (byte) 0xac, (byte) 0x7f, (byte) 0xd5, (byte) 0x1a,
        (byte) 0x4b, (byte) 0x0e, (byte) 0xa7, (byte) 0x5a,
        (byte) 0x28, (byte) 0x14, (byte) 0x3f, (byte) 0x29,
        (byte) 0x88, (byte) 0x3c, (byte) 0x4c, (byte) 0x02,
        (byte) 0xb8, (byte) 0xda, (byte) 0xb0, (byte) 0x17,
        (byte) 0x55, (byte) 0x1f, (byte) 0x8a, (byte) 0x7d,
        (byte) 0x57, (byte) 0xc7, (byte) 0x8d, (byte) 0x74,
        (byte) 0xb7, (byte) 0xc4, (byte) 0x9f, (byte) 0x72,
        (byte) 0x7e, (byte) 0x15, (byte) 0x22, (byte) 0x12,
        (byte) 0x58, (byte) 0x07, (byte) 0x99, (byte) 0x34,
        (byte) 0x6e, (byte) 0x50, (byte) 0xde, (byte) 0x68,
        (byte) 0x65, (byte) 0xbc, (byte) 0xdb, (byte) 0xf8,
        (byte) 0xc8, (byte) 0xa8, (byte) 0x2b, (byte) 0x40,
        (byte) 0xdc, (byte) 0xfe, (byte) 0x32, (byte) 0xa4,
        (byte) 0xca, (byte) 0x10, (byte) 0x21, (byte) 0xf0,
        (byte) 0xd3, (byte) 0x5d, (byte) 0x0f, (byte) 0x00,
        (byte) 0x6f, (byte) 0x9d, (byte) 0x36, (byte) 0x42,
        (byte) 0x4a, (byte) 0x5e, (byte) 0xc1, (byte) 0xe0 },
    {  // p1
        (byte) 0x75, (byte) 0xf3, (byte) 0xc6, (byte) 0xf4,
        (byte) 0xdb, (byte) 0x7b, (byte) 0xfb, (byte) 0xc8,
        (byte) 0x4a, (byte) 0xd3, (byte) 0xe6, (byte) 0x6b,
        (byte) 0x45, (byte) 0x7d, (byte) 0xe8, (byte) 0x4b,
        (byte) 0xd6, (byte) 0x32, (byte) 0xd8, (byte) 0xfd,
        (byte) 0x37, (byte) 0x71, (byte) 0xf1, (byte) 0xe1,
        (byte) 0x30, (byte) 0x0f, (byte) 0xf8, (byte) 0x1b,
        (byte) 0x87, (byte) 0xfa, (byte) 0x06, (byte) 0x3f,
        (byte) 0x5e, (byte) 0xba, (byte) 0xae, (byte) 0x5b,
        (byte) 0x8a, (byte) 0x00, (byte) 0xbc, (byte) 0x9d,
        (byte) 0x6d, (byte) 0xc1, (byte) 0xb1, (byte) 0x0e,
        (byte) 0x80, (byte) 0x5d, (byte) 0xd2, (byte) 0xd5,
        (byte) 0xa0, (byte) 0x84, (byte) 0x07, (byte) 0x14,
        (byte) 0xb5, (byte) 0x90, (byte) 0x2c, (byte) 0xa3,
        (byte) 0xb2, (byte) 0x73, (byte) 0x4c, (byte) 0x54,
        (byte) 0x92, (byte) 0x74, (byte) 0x36, (byte) 0x51,
        (byte) 0x38, (byte) 0xb0, (byte) 0xbd, (byte) 0x5a,
        (byte) 0xfc, (byte) 0x60, (byte) 0x62, (byte) 0x96,
        (byte) 0x6c, (byte) 0x42, (byte) 0xf7, (byte) 0x10,
        (byte) 0x7c, (byte) 0x28, (byte) 0x27, (byte) 0x8c,
        (byte) 0x13, (byte) 0x95, (byte) 0x9c, (byte) 0xc7,
        (byte) 0x24, (byte) 0x46, (byte) 0x3b, (byte) 0x70,
        (byte) 0xca, (byte) 0xe3, (byte) 0x85, (byte) 0xcb,
        (byte) 0x11, (byte) 0xd0, (byte) 0x93, (byte) 0xb8,
        (byte) 0xa6, (byte) 0x83, (byte) 0x20, (byte) 0xff,
        (byte) 0x9f, (byte) 0x77, (byte) 0xc3, (byte) 0xcc,
        (byte) 0x03, (byte) 0x6f, (byte) 0x08, (byte) 0xbf,
        (byte) 0x40, (byte) 0xe7, (byte) 0x2b, (byte) 0xe2,
        (byte) 0x79, (byte) 0x0c, (byte) 0xaa, (byte) 0x82,
        (byte) 0x41, (byte) 0x3a, (byte) 0xea, (byte) 0xb9,
        (byte) 0xe4, (byte) 0x9a, (byte) 0xa4, (byte) 0x97,
        (byte) 0x7e, (byte) 0xda, (byte) 0x7a, (byte) 0x17,
        (byte) 0x66, (byte) 0x94, (byte) 0xa1, (byte) 0x1d,
        (byte) 0x3d, (byte) 0xf0, (byte) 0xde, (byte) 0xb3,
        (byte) 0x0b, (byte) 0x72, (byte) 0xa7, (byte) 0x1c,
        (byte) 0xef, (byte) 0xd1, (byte) 0x53, (byte) 0x3e,
        (byte) 0x8f, (byte) 0x33, (byte) 0x26, (byte) 0x5f,
        (byte) 0xec, (byte) 0x76, (byte) 0x2a, (byte) 0x49,
        (byte) 0x81, (byte) 0x88, (byte) 0xee, (byte) 0x21,
        (byte) 0xc4, (byte) 0x1a, (byte) 0xeb, (byte) 0xd9,
        (byte) 0xc5, (byte) 0x39, (byte) 0x99, (byte) 0xcd,
        (byte) 0xad, (byte) 0x31, (byte) 0x8b, (byte) 0x01,
        (byte) 0x18, (byte) 0x23, (byte) 0xdd, (byte) 0x1f,
        (byte) 0x4e, (byte) 0x2d, (byte) 0xf9, (byte) 0x48,
        (byte) 0x4f, (byte) 0xf2, (byte) 0x65, (byte) 0x8e,
        (byte) 0x78, (byte) 0x5c, (byte) 0x58, (byte) 0x19,
        (byte) 0x8d, (byte) 0xe5, (byte) 0x98, (byte) 0x57,
        (byte) 0x67, (byte) 0x7f, (byte) 0x05, (byte) 0x64,
        (byte) 0xaf, (byte) 0x63, (byte) 0xb6, (byte) 0xfe,
        (byte) 0xf5, (byte) 0xb7, (byte) 0x3c, (byte) 0xa5,
        (byte) 0xce, (byte) 0xe9, (byte) 0x68, (byte) 0x44,
        (byte) 0xe0, (byte) 0x4d, (byte) 0x43, (byte) 0x69,
        (byte) 0x29, (byte) 0x2e, (byte) 0xac, (byte) 0x15,
        (byte) 0x59, (byte) 0xa8, (byte) 0x0a, (byte) 0x9e,
        (byte) 0x6e, (byte) 0x47, (byte) 0xdf, (byte) 0x34,
        (byte) 0x35, (byte) 0x6a, (byte) 0xcf, (byte) 0xdc,
        (byte) 0x22, (byte) 0xc9, (byte) 0xc0, (byte) 0x9b,
        (byte) 0x89, (byte) 0xd4, (byte) 0xed, (byte) 0xab,
        (byte) 0x12, (byte) 0xa2, (byte) 0x0d, (byte) 0x52,
        (byte) 0xbb, (byte) 0x02, (byte) 0x2f, (byte) 0xa9,
        (byte) 0xd7, (byte) 0x61, (byte) 0x1e, (byte) 0xb4,
        (byte) 0x50, (byte) 0x04, (byte) 0xf6, (byte) 0xc2,
        (byte) 0x16, (byte) 0x25, (byte) 0x86, (byte) 0x56,
        (byte) 0x55, (byte) 0x09, (byte) 0xbe, (byte) 0x91  }
    };

    /**
    * define the fixed p0/p1 permutations used in keyed s-box lookup.
    * by changing the following constant definitions, the s-boxes will
    * automatically get changed in the twofish engine.
    */
    private static final int p_00 = 1;
    private static final int p_01 = 0;
    private static final int p_02 = 0;
    private static final int p_03 = p_01 ^ 1;
    private static final int p_04 = 1;

    private static final int p_10 = 0;
    private static final int p_11 = 0;
    private static final int p_12 = 1;
    private static final int p_13 = p_11 ^ 1;
    private static final int p_14 = 0;

    private static final int p_20 = 1;
    private static final int p_21 = 1;
    private static final int p_22 = 0;
    private static final int p_23 = p_21 ^ 1;
    private static final int p_24 = 0;

    private static final int p_30 = 0;
    private static final int p_31 = 1;
    private static final int p_32 = 1;
    private static final int p_33 = p_31 ^ 1;
    private static final int p_34 = 1;

    /* primitive polynomial for gf(256) */
    private static final int gf256_fdbk =   0x169;
    private static final int gf256_fdbk_2 = gf256_fdbk / 2;
    private static final int gf256_fdbk_4 = gf256_fdbk / 4;

    private static final int rs_gf_fdbk = 0x14d; // field generator

    //====================================
    // useful constants
    //====================================

    private static final int    rounds = 16;
    private static final int    max_rounds = 16;  // bytes = 128 bits
    private static final int    block_size = 16;  // bytes = 128 bits
    private static final int    max_key_bits = 256;

    private static final int    input_whiten=0;
    private static final int    output_whiten=input_whiten+block_size/4; // 4
    private static final int    round_subkeys=output_whiten+block_size/4;// 8

    private static final int    total_subkeys=round_subkeys+2*max_rounds;// 40

    private static final int    sk_step = 0x02020202;
    private static final int    sk_bump = 0x01010101;
    private static final int    sk_rotl = 9;

    private boolean encrypting = false;

    private int[] gmds0 = new int[max_key_bits];
    private int[] gmds1 = new int[max_key_bits];
    private int[] gmds2 = new int[max_key_bits];
    private int[] gmds3 = new int[max_key_bits];

    /**
     * gsubkeys[] and gsbox[] are eventually used in the 
     * encryption and decryption methods.
     */
    private int[] gsubkeys;
    private int[] gsbox;

    private int k64cnt = 0;

    private byte[] workingkey = null;

    public twofishengine()
    {
        // calculate the mds matrix
        int[] m1 = new int[2];
        int[] mx = new int[2];
        int[] my = new int[2];
        int j;

        for (int i=0; i< max_key_bits ; i++)
        {
            j = p[0][i] & 0xff;
            m1[0] = j;
            mx[0] = mx_x(j) & 0xff;
            my[0] = mx_y(j) & 0xff;

            j = p[1][i] & 0xff;
            m1[1] = j;
            mx[1] = mx_x(j) & 0xff;
            my[1] = mx_y(j) & 0xff;

            gmds0[i] = m1[p_00]       | mx[p_00] <<  8 |
                         my[p_00] << 16 | my[p_00] << 24;

            gmds1[i] = my[p_10]       | my[p_10] <<  8 |
                         mx[p_10] << 16 | m1[p_10] << 24;

            gmds2[i] = mx[p_20]       | my[p_20] <<  8 |
                         m1[p_20] << 16 | my[p_20] << 24;

            gmds3[i] = mx[p_30]       | m1[p_30] <<  8 |
                         my[p_30] << 16 | mx[p_30] << 24;
        }
    }

    /**
     * initialise a twofish cipher.
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
            this.workingkey = ((keyparameter)params).getkey();
            this.k64cnt = (this.workingkey.length / 8); // pre-padded ?
            setkey(this.workingkey);

            return;
        }

        throw new illegalargumentexception("invalid parameter passed to twofish init - " + params.getclass().getname());
    }

    public string getalgorithmname()
    {
        return "twofish";
    }

    public int processblock(
        byte[] in,
        int inoff,
        byte[] out,
        int outoff)
    {
        if (workingkey == null)
        {
            throw new illegalstateexception("twofish not initialised");
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
        if (this.workingkey != null)
        {
            setkey(this.workingkey);
        }
    }

    public int getblocksize()
    {
        return block_size;
    }

    //==================================
    // private implementation
    //==================================

    private void setkey(byte[] key)
    {
        int[] k32e = new int[max_key_bits/64]; // 4
        int[] k32o = new int[max_key_bits/64]; // 4 

        int[] sboxkeys = new int[max_key_bits/64]; // 4 
        gsubkeys = new int[total_subkeys];

        if (k64cnt < 1) 
        {
            throw new illegalargumentexception("key size less than 64 bits");
        }
        
        if (k64cnt > 4)
        {
            throw new illegalargumentexception("key size larger than 256 bits");
        }

        /*
         * k64cnt is the number of 8 byte blocks (64 chunks)
         * that are in the input key.  the input key is a
         * maximum of 32 bytes (256 bits), so the range
         * for k64cnt is 1..4
         */
        for (int i=0; i<k64cnt ; i++)
        {
            int p = i* 8;

            k32e[i] = bytesto32bits(key, p);
            k32o[i] = bytesto32bits(key, p+4);

            sboxkeys[k64cnt-1-i] = rs_mds_encode(k32e[i], k32o[i]);
        }

        int q,a,b;
        for (int i=0; i < total_subkeys / 2 ; i++) 
        {
            q = i*sk_step;
            a = f32(q,         k32e);
            b = f32(q+sk_bump, k32o);
            b = b << 8 | b >>> 24;
            a += b;
            gsubkeys[i*2] = a;
            a += b;
            gsubkeys[i*2 + 1] = a << sk_rotl | a >>> (32-sk_rotl);
        }

        /*
         * fully expand the table for speed
         */
        int k0 = sboxkeys[0];
        int k1 = sboxkeys[1];
        int k2 = sboxkeys[2];
        int k3 = sboxkeys[3];
        int b0, b1, b2, b3;
        gsbox = new int[4*max_key_bits];
        for (int i=0; i<max_key_bits; i++)
        {
            b0 = b1 = b2 = b3 = i;
            switch (k64cnt & 3)
            {
                case 1:
                    gsbox[i*2]       = gmds0[(p[p_01][b0] & 0xff) ^ b0(k0)];
                    gsbox[i*2+1]     = gmds1[(p[p_11][b1] & 0xff) ^ b1(k0)];
                    gsbox[i*2+0x200] = gmds2[(p[p_21][b2] & 0xff) ^ b2(k0)];
                    gsbox[i*2+0x201] = gmds3[(p[p_31][b3] & 0xff) ^ b3(k0)];
                break;
                case 0: // 256 bits of key
                    b0 = (p[p_04][b0] & 0xff) ^ b0(k3);
                    b1 = (p[p_14][b1] & 0xff) ^ b1(k3);
                    b2 = (p[p_24][b2] & 0xff) ^ b2(k3);
                    b3 = (p[p_34][b3] & 0xff) ^ b3(k3);
                    // fall through, having pre-processed b[0]..b[3] with k32[3]
                case 3: // 192 bits of key
                    b0 = (p[p_03][b0] & 0xff) ^ b0(k2);
                    b1 = (p[p_13][b1] & 0xff) ^ b1(k2);
                    b2 = (p[p_23][b2] & 0xff) ^ b2(k2);
                    b3 = (p[p_33][b3] & 0xff) ^ b3(k2);
                    // fall through, having pre-processed b[0]..b[3] with k32[2]
                case 2: // 128 bits of key
                    gsbox[i*2]   = gmds0[(p[p_01]
                        [(p[p_02][b0] & 0xff) ^ b0(k1)] & 0xff) ^ b0(k0)];
                    gsbox[i*2+1] = gmds1[(p[p_11]
                        [(p[p_12][b1] & 0xff) ^ b1(k1)] & 0xff) ^ b1(k0)];
                    gsbox[i*2+0x200] = gmds2[(p[p_21]
                        [(p[p_22][b2] & 0xff) ^ b2(k1)] & 0xff) ^ b2(k0)];
                    gsbox[i*2+0x201] = gmds3[(p[p_31]
                        [(p[p_32][b3] & 0xff) ^ b3(k1)] & 0xff) ^ b3(k0)];
                break;
            }
        }

        /* 
         * the function exits having setup the gsbox with the 
         * input key material.
         */
    }

    /**
     * encrypt the given input starting at the given offset and place
     * the result in the provided buffer starting at the given offset.
     * the input will be an exact multiple of our blocksize.
     *
     * encryptblock uses the pre-calculated gsbox[] and subkey[]
     * arrays.
     */
    private void encryptblock(
        byte[] src, 
        int srcindex,
        byte[] dst,
        int dstindex)
    {
        int x0 = bytesto32bits(src, srcindex) ^ gsubkeys[input_whiten];
        int x1 = bytesto32bits(src, srcindex + 4) ^ gsubkeys[input_whiten + 1];
        int x2 = bytesto32bits(src, srcindex + 8) ^ gsubkeys[input_whiten + 2];
        int x3 = bytesto32bits(src, srcindex + 12) ^ gsubkeys[input_whiten + 3];

        int k = round_subkeys;
        int t0, t1;
        for (int r = 0; r < rounds; r +=2)
        {
            t0 = fe32_0(x0);
            t1 = fe32_3(x1);
            x2 ^= t0 + t1 + gsubkeys[k++];
            x2 = x2 >>>1 | x2 << 31;
            x3 = (x3 << 1 | x3 >>> 31) ^ (t0 + 2*t1 + gsubkeys[k++]);

            t0 = fe32_0(x2);
            t1 = fe32_3(x3);
            x0 ^= t0 + t1 + gsubkeys[k++];
            x0 = x0 >>>1 | x0 << 31;
            x1 = (x1 << 1 | x1 >>> 31) ^ (t0 + 2*t1 + gsubkeys[k++]);
        }

        bits32tobytes(x2 ^ gsubkeys[output_whiten], dst, dstindex);
        bits32tobytes(x3 ^ gsubkeys[output_whiten + 1], dst, dstindex + 4);
        bits32tobytes(x0 ^ gsubkeys[output_whiten + 2], dst, dstindex + 8);
        bits32tobytes(x1 ^ gsubkeys[output_whiten + 3], dst, dstindex + 12);
    }

    /**
     * decrypt the given input starting at the given offset and place
     * the result in the provided buffer starting at the given offset.
     * the input will be an exact multiple of our blocksize.
     */
    private void decryptblock(
        byte[] src, 
        int srcindex,
        byte[] dst,
        int dstindex)
    {
        int x2 = bytesto32bits(src, srcindex) ^ gsubkeys[output_whiten];
        int x3 = bytesto32bits(src, srcindex+4) ^ gsubkeys[output_whiten + 1];
        int x0 = bytesto32bits(src, srcindex+8) ^ gsubkeys[output_whiten + 2];
        int x1 = bytesto32bits(src, srcindex+12) ^ gsubkeys[output_whiten + 3];

        int k = round_subkeys + 2 * rounds -1 ;
        int t0, t1;
        for (int r = 0; r< rounds ; r +=2)
        {
            t0 = fe32_0(x2);
            t1 = fe32_3(x3);
            x1 ^= t0 + 2*t1 + gsubkeys[k--];
            x0 = (x0 << 1 | x0 >>> 31) ^ (t0 + t1 + gsubkeys[k--]);
            x1 = x1 >>>1 | x1 << 31;

            t0 = fe32_0(x0);
            t1 = fe32_3(x1);
            x3 ^= t0 + 2*t1 + gsubkeys[k--];
            x2 = (x2 << 1 | x2 >>> 31) ^ (t0 + t1 + gsubkeys[k--]);
            x3 = x3 >>>1 | x3 << 31;
        }

        bits32tobytes(x0 ^ gsubkeys[input_whiten], dst, dstindex);
        bits32tobytes(x1 ^ gsubkeys[input_whiten + 1], dst, dstindex + 4);
        bits32tobytes(x2 ^ gsubkeys[input_whiten + 2], dst, dstindex + 8);
        bits32tobytes(x3 ^ gsubkeys[input_whiten + 3], dst, dstindex + 12);
    }

    /* 
     * todo:  this can be optimised and made cleaner by combining
     * the functionality in this function and applying it appropriately
     * to the creation of the subkeys during key setup.
     */
    private int f32(int x, int[] k32)
    {
        int b0 = b0(x);
        int b1 = b1(x);
        int b2 = b2(x);
        int b3 = b3(x);
        int k0 = k32[0];
        int k1 = k32[1];
        int k2 = k32[2];
        int k3 = k32[3];

        int result = 0;
        switch (k64cnt & 3)
        {
            case 1:
                result = gmds0[(p[p_01][b0] & 0xff) ^ b0(k0)] ^
                         gmds1[(p[p_11][b1] & 0xff) ^ b1(k0)] ^
                         gmds2[(p[p_21][b2] & 0xff) ^ b2(k0)] ^
                         gmds3[(p[p_31][b3] & 0xff) ^ b3(k0)];
                break;
            case 0: /* 256 bits of key */
                b0 = (p[p_04][b0] & 0xff) ^ b0(k3);
                b1 = (p[p_14][b1] & 0xff) ^ b1(k3);
                b2 = (p[p_24][b2] & 0xff) ^ b2(k3);
                b3 = (p[p_34][b3] & 0xff) ^ b3(k3);
            case 3: 
                b0 = (p[p_03][b0] & 0xff) ^ b0(k2);
                b1 = (p[p_13][b1] & 0xff) ^ b1(k2);
                b2 = (p[p_23][b2] & 0xff) ^ b2(k2);
                b3 = (p[p_33][b3] & 0xff) ^ b3(k2);
            case 2:
                result = 
                gmds0[(p[p_01][(p[p_02][b0]&0xff)^b0(k1)]&0xff)^b0(k0)] ^ 
                gmds1[(p[p_11][(p[p_12][b1]&0xff)^b1(k1)]&0xff)^b1(k0)] ^
                gmds2[(p[p_21][(p[p_22][b2]&0xff)^b2(k1)]&0xff)^b2(k0)] ^
                gmds3[(p[p_31][(p[p_32][b3]&0xff)^b3(k1)]&0xff)^b3(k0)];
            break;
        }
        return result;
    }

    /**
     * use (12, 8) reed-solomon code over gf(256) to produce
     * a key s-box 32-bit entity from 2 key material 32-bit
     * entities.
     *
     * @param    k0 first 32-bit entity
     * @param    k1 second 32-bit entity
     * @return     remainder polynomial generated using rs code
     */
    private int rs_mds_encode(int k0, int k1)
    {
        int r = k1;
        for (int i = 0 ; i < 4 ; i++) // shift 1 byte at a time
        {
            r = rs_rem(r);
        }
        r ^= k0;
        for (int i=0 ; i < 4 ; i++)
        {
            r = rs_rem(r);
        }

        return r;
    }

    /**
     * reed-solomon code parameters: (12,8) reversible code:<p>
     * <pre>
     * g(x) = x^4 + (a+1/a)x^3 + ax^2 + (a+1/a)x + 1
     * </pre>
     * where a = primitive root of field generator 0x14d
     */
    private int rs_rem(int x)
    {
        int b = (x >>> 24) & 0xff;
        int g2 = ((b << 1) ^ 
                 ((b & 0x80) != 0 ? rs_gf_fdbk : 0)) & 0xff;
        int g3 = ((b >>> 1) ^ 
                 ((b & 0x01) != 0 ? (rs_gf_fdbk >>> 1) : 0)) ^ g2 ;
        return ((x << 8) ^ (g3 << 24) ^ (g2 << 16) ^ (g3 << 8) ^ b);
    }
        
    private int lfsr1(int x)
    {
        return (x >> 1) ^ 
                (((x & 0x01) != 0) ? gf256_fdbk_2 : 0);
    }

    private int lfsr2(int x)
    {
        return (x >> 2) ^
                (((x & 0x02) != 0) ? gf256_fdbk_2 : 0) ^
                (((x & 0x01) != 0) ? gf256_fdbk_4 : 0);
    }

    private int mx_x(int x)
    {
        return x ^ lfsr2(x);
    } // 5b

    private int mx_y(int x)
    {
        return x ^ lfsr1(x) ^ lfsr2(x);
    } // ef

    private int b0(int x)
    {
        return x & 0xff;
    }

    private int b1(int x)
    {
        return (x >>> 8) & 0xff;
    }

    private int b2(int x)
    {
        return (x >>> 16) & 0xff;
    }

    private int b3(int x)
    {
        return (x >>> 24) & 0xff;
    }

    private int fe32_0(int x)
    {
        return gsbox[ 0x000 + 2*(x & 0xff) ] ^
               gsbox[ 0x001 + 2*((x >>> 8) & 0xff) ] ^
               gsbox[ 0x200 + 2*((x >>> 16) & 0xff) ] ^
               gsbox[ 0x201 + 2*((x >>> 24) & 0xff) ];
    }
    
    private int fe32_3(int x)
    {
        return gsbox[ 0x000 + 2*((x >>> 24) & 0xff) ] ^
               gsbox[ 0x001 + 2*(x & 0xff) ] ^
               gsbox[ 0x200 + 2*((x >>> 8) & 0xff) ] ^
               gsbox[ 0x201 + 2*((x >>> 16) & 0xff) ];
    }
    
    private int bytesto32bits(byte[] b, int p)
    {
        return ((b[p] & 0xff)) | 
             ((b[p+1] & 0xff) << 8) |
             ((b[p+2] & 0xff) << 16) |
             ((b[p+3] & 0xff) << 24);
    }

    private void bits32tobytes(int in,  byte[] b, int offset)
    {
        b[offset] = (byte)in;
        b[offset + 1] = (byte)(in >> 8);
        b[offset + 2] = (byte)(in >> 16);
        b[offset + 3] = (byte)(in >> 24);
    }
}
