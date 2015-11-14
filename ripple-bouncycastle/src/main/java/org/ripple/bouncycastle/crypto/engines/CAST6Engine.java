package org.ripple.bouncycastle.crypto.engines;


/**
 * a class that provides cast6 key encryption operations,
 * such as encoding data and generating keys.
 *
 * all the algorithms herein are from the internet rfc
 *
 * rfc2612 - cast6 (128bit block, 128-256bit key)
 *
 * and implement a simplified cryptography interface.
 */
public final class cast6engine extends cast5engine
{
    //====================================
    // useful constants
    //====================================

    protected static final int    rounds = 12;

    protected static final int    block_size = 16;  // bytes = 128 bits

    /*
     * put the round and mask keys into an array.
     * kr0[i] => _kr[i*4 + 0]
     */
    protected int _kr[] = new int[rounds*4]; // the rotating round key(s)
    protected int _km[] = new int[rounds*4]; // the masking round key(s)

    /*
     * key setup
     */
    protected int _tr[] = new int[24 * 8];
    protected int _tm[] = new int[24 * 8];

    private int[] _workingkey = new int[8];

    public cast6engine()
    {
    }

    public string getalgorithmname()
    {
        return "cast6";
    }

    public void reset()
    {
    }

    public int getblocksize()
    {
        return block_size;
    }

    //==================================
    // private implementation
    //==================================

    /*
     * creates the subkeys using the same nomenclature
     * as described in rfc2612.
     *
     * see section 2.4
     */
    protected void setkey(byte[] key)
    {
        int cm = 0x5a827999;
        int mm = 0x6ed9eba1;
        int cr = 19;
        int mr = 17;

        /* 
         * determine the key size here, if required
         *
         * if keysize < 256 bytes, pad with 0
         *
         * typical key sizes => 128, 160, 192, 224, 256
         */
        for (int i=0; i< 24; i++)
        {
            for (int j=0; j< 8; j++)
            {
                _tm[i*8 + j] = cm;
                cm = (cm + mm);    // mod 2^32;

                _tr[i*8 + j] = cr;
                cr = (cr + mr) & 0x1f;            // mod 32
            }
        }

        byte[] tmpkey = new byte[64];
        int length = key.length;
        system.arraycopy(key, 0, tmpkey, 0, length);

        // now create abcdefgh
        for (int i=0; i< 8; i++)
        {
            _workingkey[i] = bytesto32bits(tmpkey, i*4);
        }

        // generate the key schedule
        for (int i=0; i< 12; i++)
        {
            // kappa <- w2i(kappa)
            int i2 = i*2 *8;
            _workingkey[6] ^= f1(_workingkey[7], _tm[i2  ], _tr[i2  ]);
            _workingkey[5] ^= f2(_workingkey[6], _tm[i2+1], _tr[i2+1]);
            _workingkey[4] ^= f3(_workingkey[5], _tm[i2+2], _tr[i2+2]);
            _workingkey[3] ^= f1(_workingkey[4], _tm[i2+3], _tr[i2+3]);
            _workingkey[2] ^= f2(_workingkey[3], _tm[i2+4], _tr[i2+4]);
            _workingkey[1] ^= f3(_workingkey[2], _tm[i2+5], _tr[i2+5]);
            _workingkey[0] ^= f1(_workingkey[1], _tm[i2+6], _tr[i2+6]);
            _workingkey[7] ^= f2(_workingkey[0], _tm[i2+7], _tr[i2+7]);

            // kappa <- w2i+1(kappa)
            i2 = (i*2 + 1)*8;
            _workingkey[6] ^= f1(_workingkey[7], _tm[i2  ], _tr[i2  ]);
            _workingkey[5] ^= f2(_workingkey[6], _tm[i2+1], _tr[i2+1]);
            _workingkey[4] ^= f3(_workingkey[5], _tm[i2+2], _tr[i2+2]);
            _workingkey[3] ^= f1(_workingkey[4], _tm[i2+3], _tr[i2+3]);
            _workingkey[2] ^= f2(_workingkey[3], _tm[i2+4], _tr[i2+4]);
            _workingkey[1] ^= f3(_workingkey[2], _tm[i2+5], _tr[i2+5]);
            _workingkey[0] ^= f1(_workingkey[1], _tm[i2+6], _tr[i2+6]);
            _workingkey[7] ^= f2(_workingkey[0], _tm[i2+7], _tr[i2+7]);

            // kr_(i) <- kappa
            _kr[i*4    ] = _workingkey[0] & 0x1f;
            _kr[i*4 + 1] = _workingkey[2] & 0x1f;
            _kr[i*4 + 2] = _workingkey[4] & 0x1f;
            _kr[i*4 + 3] = _workingkey[6] & 0x1f;


            // km_(i) <- kappa
            _km[i*4    ] = _workingkey[7];
            _km[i*4 + 1] = _workingkey[5];
            _km[i*4 + 2] = _workingkey[3];
            _km[i*4 + 3] = _workingkey[1];
        }
        
    }

    /**
     * encrypt the given input starting at the given offset and place
     * the result in the provided buffer starting at the given offset.
     *
     * @param src        the plaintext buffer
     * @param srcindex    an offset into src
     * @param dst        the ciphertext buffer
     * @param dstindex    an offset into dst
     */
    protected int encryptblock(
        byte[] src, 
        int srcindex,
        byte[] dst,
        int dstindex)
    {

        int  result[] = new int[4];

        // process the input block 
        // batch the units up into 4x32 bit chunks and go for it

        int a = bytesto32bits(src, srcindex);
        int b = bytesto32bits(src, srcindex + 4);
        int c = bytesto32bits(src, srcindex + 8);
        int d = bytesto32bits(src, srcindex + 12);

        cast_encipher(a, b, c, d, result);

        // now stuff them into the destination block
        bits32tobytes(result[0], dst, dstindex);
        bits32tobytes(result[1], dst, dstindex + 4);
        bits32tobytes(result[2], dst, dstindex + 8);
        bits32tobytes(result[3], dst, dstindex + 12);

        return block_size;
    }

    /**
     * decrypt the given input starting at the given offset and place
     * the result in the provided buffer starting at the given offset.
     *
     * @param src        the plaintext buffer
     * @param srcindex    an offset into src
     * @param dst        the ciphertext buffer
     * @param dstindex    an offset into dst
     */
    protected int decryptblock(
        byte[] src, 
        int srcindex,
        byte[] dst,
        int dstindex)
    {
        int  result[] = new int[4];

        // process the input block
        // batch the units up into 4x32 bit chunks and go for it
        int a = bytesto32bits(src, srcindex);
        int b = bytesto32bits(src, srcindex + 4);
        int c = bytesto32bits(src, srcindex + 8);
        int d = bytesto32bits(src, srcindex + 12);

        cast_decipher(a, b, c, d, result);

        // now stuff them into the destination block
        bits32tobytes(result[0], dst, dstindex);
        bits32tobytes(result[1], dst, dstindex + 4);
        bits32tobytes(result[2], dst, dstindex + 8);
        bits32tobytes(result[3], dst, dstindex + 12);

        return block_size;
    }

    /**
     * does the 12 quad rounds rounds to encrypt the block.
     * 
     * @param a    the 00-31  bits of the plaintext block
     * @param b    the 32-63  bits of the plaintext block
     * @param c    the 64-95  bits of the plaintext block
     * @param d    the 96-127 bits of the plaintext block
     * @param result the resulting ciphertext
     */
    protected final void cast_encipher(int a, int b, int c, int d,int result[])
    {
        int x;
        for (int i=0; i< 6; i++)
        {
            x = i*4;
            // beta <- qi(beta)
            c ^= f1(d, _km[x], _kr[x]);
            b ^= f2(c, _km[x + 1], _kr[x + 1]);
            a ^= f3(b, _km[x + 2], _kr[x + 2]);
            d ^= f1(a, _km[x + 3], _kr[x + 3]);

        }

        for (int i=6; i<12; i++)
        {
            x = i*4;
            // beta <- qbari(beta)
            d ^= f1(a, _km[x + 3], _kr[x + 3]);
            a ^= f3(b, _km[x + 2], _kr[x + 2]);
            b ^= f2(c, _km[x + 1], _kr[x + 1]);
            c ^= f1(d, _km[x], _kr[x]);

        }

        result[0] = a;
        result[1] = b;
        result[2] = c;
        result[3] = d;
    }

    /**
     * does the 12 quad rounds rounds to decrypt the block.
     * 
     * @param a    the 00-31  bits of the ciphertext block
     * @param b    the 32-63  bits of the ciphertext block
     * @param c    the 64-95  bits of the ciphertext block
     * @param d    the 96-127 bits of the ciphertext block
     * @param result the resulting plaintext
     */
    protected final void cast_decipher(int a, int b, int c, int d,int result[])
    {
        int x;
        for (int i=0; i< 6; i++)
        {
            x = (11-i)*4;
            // beta <- qi(beta)
            c ^= f1(d, _km[x], _kr[x]);
            b ^= f2(c, _km[x + 1], _kr[x + 1]);
            a ^= f3(b, _km[x + 2], _kr[x + 2]);
            d ^= f1(a, _km[x + 3], _kr[x + 3]);

        }

        for (int i=6; i<12; i++)
        {
            x = (11-i)*4;
            // beta <- qbari(beta)
            d ^= f1(a, _km[x + 3], _kr[x + 3]);
            a ^= f3(b, _km[x + 2], _kr[x + 2]);
            b ^= f2(c, _km[x + 1], _kr[x + 1]);
            c ^= f1(d, _km[x], _kr[x]);

        }

        result[0] = a;
        result[1] = b;
        result[2] = c;
        result[3] = d;
    }

}
