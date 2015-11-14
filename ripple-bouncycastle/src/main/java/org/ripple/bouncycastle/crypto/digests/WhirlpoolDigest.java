package org.ripple.bouncycastle.crypto.digests;

import org.ripple.bouncycastle.crypto.extendeddigest;
import org.ripple.bouncycastle.util.arrays;
import org.ripple.bouncycastle.util.memoable;


/**
 * implementation of whirlpooldigest, based on java source published by barreto
 * and rijmen.
 *  
 */
public final class whirlpooldigest 
    implements extendeddigest, memoable
{
    private static final int byte_length = 64;
    
    private static final int digest_length_bytes = 512 / 8;
    private static final int rounds = 10;
    private static final int reduction_polynomial = 0x011d; // 2^8 + 2^4 + 2^3 + 2 + 1;

    private static final int[] sbox = {
        0x18, 0x23, 0xc6, 0xe8, 0x87, 0xb8, 0x01, 0x4f, 0x36, 0xa6, 0xd2, 0xf5, 0x79, 0x6f, 0x91, 0x52,
        0x60, 0xbc, 0x9b, 0x8e, 0xa3, 0x0c, 0x7b, 0x35, 0x1d, 0xe0, 0xd7, 0xc2, 0x2e, 0x4b, 0xfe, 0x57,
        0x15, 0x77, 0x37, 0xe5, 0x9f, 0xf0, 0x4a, 0xda, 0x58, 0xc9, 0x29, 0x0a, 0xb1, 0xa0, 0x6b, 0x85,
        0xbd, 0x5d, 0x10, 0xf4, 0xcb, 0x3e, 0x05, 0x67, 0xe4, 0x27, 0x41, 0x8b, 0xa7, 0x7d, 0x95, 0xd8,
        0xfb, 0xee, 0x7c, 0x66, 0xdd, 0x17, 0x47, 0x9e, 0xca, 0x2d, 0xbf, 0x07, 0xad, 0x5a, 0x83, 0x33,
        0x63, 0x02, 0xaa, 0x71, 0xc8, 0x19, 0x49, 0xd9, 0xf2, 0xe3, 0x5b, 0x88, 0x9a, 0x26, 0x32, 0xb0,
        0xe9, 0x0f, 0xd5, 0x80, 0xbe, 0xcd, 0x34, 0x48, 0xff, 0x7a, 0x90, 0x5f, 0x20, 0x68, 0x1a, 0xae,
        0xb4, 0x54, 0x93, 0x22, 0x64, 0xf1, 0x73, 0x12, 0x40, 0x08, 0xc3, 0xec, 0xdb, 0xa1, 0x8d, 0x3d,
        0x97, 0x00, 0xcf, 0x2b, 0x76, 0x82, 0xd6, 0x1b, 0xb5, 0xaf, 0x6a, 0x50, 0x45, 0xf3, 0x30, 0xef,
        0x3f, 0x55, 0xa2, 0xea, 0x65, 0xba, 0x2f, 0xc0, 0xde, 0x1c, 0xfd, 0x4d, 0x92, 0x75, 0x06, 0x8a,
        0xb2, 0xe6, 0x0e, 0x1f, 0x62, 0xd4, 0xa8, 0x96, 0xf9, 0xc5, 0x25, 0x59, 0x84, 0x72, 0x39, 0x4c,
        0x5e, 0x78, 0x38, 0x8c, 0xd1, 0xa5, 0xe2, 0x61, 0xb3, 0x21, 0x9c, 0x1e, 0x43, 0xc7, 0xfc, 0x04,
        0x51, 0x99, 0x6d, 0x0d, 0xfa, 0xdf, 0x7e, 0x24, 0x3b, 0xab, 0xce, 0x11, 0x8f, 0x4e, 0xb7, 0xeb,
        0x3c, 0x81, 0x94, 0xf7, 0xb9, 0x13, 0x2c, 0xd3, 0xe7, 0x6e, 0xc4, 0x03, 0x56, 0x44, 0x7f, 0xa9,
        0x2a, 0xbb, 0xc1, 0x53, 0xdc, 0x0b, 0x9d, 0x6c, 0x31, 0x74, 0xf6, 0x46, 0xac, 0x89, 0x14, 0xe1,
        0x16, 0x3a, 0x69, 0x09, 0x70, 0xb6, 0xd0, 0xed, 0xcc, 0x42, 0x98, 0xa4, 0x28, 0x5c, 0xf8, 0x86
    };
    
    private static final long[] c0 = new long[256];
    private static final long[] c1 = new long[256];
    private static final long[] c2 = new long[256];
    private static final long[] c3 = new long[256];
    private static final long[] c4 = new long[256];
    private static final long[] c5 = new long[256];
    private static final long[] c6 = new long[256];
    private static final long[] c7 = new long[256];

    private final long[] _rc = new long[rounds + 1];
        
    public whirlpooldigest()
    {
        for (int i = 0; i < 256; i++)
        {
            int v1 = sbox[i];
            int v2 = maskwithreductionpolynomial(v1 << 1);
            int v4 = maskwithreductionpolynomial(v2 << 1);
            int v5 = v4 ^ v1;
            int v8 = maskwithreductionpolynomial(v4 << 1);
            int v9 = v8 ^ v1;
            
            c0[i] = packintolong(v1, v1, v4, v1, v8, v5, v2, v9);
            c1[i] = packintolong(v9, v1, v1, v4, v1, v8, v5, v2);
            c2[i] = packintolong(v2, v9, v1, v1, v4, v1, v8, v5);
            c3[i] = packintolong(v5, v2, v9, v1, v1, v4, v1, v8);
            c4[i] = packintolong(v8, v5, v2, v9, v1, v1, v4, v1);
            c5[i] = packintolong(v1, v8, v5, v2, v9, v1, v1, v4);
            c6[i] = packintolong(v4, v1, v8, v5, v2, v9, v1, v1);
            c7[i] = packintolong(v1, v4, v1, v8, v5, v2, v9, v1);
            
        }
        
        _rc[0] = 0l;
        for (int r = 1; r <= rounds; r++)
        {
            int i = 8 * (r - 1);
            _rc[r] =    (c0[i    ] & 0xff00000000000000l) ^ 
                        (c1[i + 1] & 0x00ff000000000000l) ^ 
                        (c2[i + 2] & 0x0000ff0000000000l) ^
                        (c3[i + 3] & 0x000000ff00000000l) ^ 
                        (c4[i + 4] & 0x00000000ff000000l) ^
                        (c5[i + 5] & 0x0000000000ff0000l) ^
                        (c6[i + 6] & 0x000000000000ff00l) ^ 
                        (c7[i + 7] & 0x00000000000000ffl);
        }
        
    }

    private long packintolong(int b7, int b6, int b5, int b4, int b3, int b2, int b1, int b0)
    {
        return 
                    ((long)b7 << 56) ^
                    ((long)b6 << 48) ^
                    ((long)b5 << 40) ^
                    ((long)b4 << 32) ^
                    ((long)b3 << 24) ^
                    ((long)b2 << 16) ^
                    ((long)b1 <<  8) ^
                    b0;
    }

    /*
     * int's are used to prevent sign extension.  the values that are really being used are
     * actually just 0..255
     */
    private int maskwithreductionpolynomial(int input)
    {
        int rv = input;
        if (rv >= 0x100l) // high bit set
        {
            rv ^= reduction_polynomial; // reduced by the polynomial
        }
        return rv;
    }
        
    // --------------------------------------------------------------------------------------//
    
    // -- buffer information --
    private static final int bitcount_array_size = 32;
    private byte[]  _buffer    = new byte[64];
    private int     _bufferpos = 0;
    private short[] _bitcount  = new short[bitcount_array_size];
    
    // -- internal hash state --
    private long[] _hash  = new long[8];
    private long[] _k = new long[8]; // the round key
    private long[] _l = new long[8];
    private long[] _block = new long[8]; // mu (buffer)
    private long[] _state = new long[8]; // the current "cipher" state
    


    /**
     * copy constructor. this will copy the state of the provided message
     * digest.
     */
    public whirlpooldigest(whirlpooldigest originaldigest)
    {
        reset(originaldigest);
    }

    public string getalgorithmname()
    {
        return "whirlpool";
    }

    public int getdigestsize()
    {
        return digest_length_bytes;
    }

    public int dofinal(byte[] out, int outoff)
    {
        // sets out[outoff] .. out[outoff+digest_length_bytes]
        finish();

        for (int i = 0; i < 8; i++)
        {
            convertlongtobytearray(_hash[i], out, outoff + (i * 8));
        }

        reset();        
        return getdigestsize();
    }
    
    /**
     * reset the chaining variables
     */
    public void reset()
    {
        // set variables to null, blank, whatever
        _bufferpos = 0;
        arrays.fill(_bitcount, (short)0);
        arrays.fill(_buffer, (byte)0);
        arrays.fill(_hash, 0);
        arrays.fill(_k, 0);
        arrays.fill(_l, 0);
        arrays.fill(_block, 0);
        arrays.fill(_state, 0);
    }

    // this takes a buffer of information and fills the block
    private void processfilledbuffer(byte[] in, int inoff)
    {
        // copies into the block...
        for (int i = 0; i < _state.length; i++)
        {
            _block[i] = bytestolongfrombuffer(_buffer, i * 8);
        }
        processblock();
        _bufferpos = 0;
        arrays.fill(_buffer, (byte)0);
    }

    private long bytestolongfrombuffer(byte[] buffer, int startpos)
    {
        long rv = (((buffer[startpos + 0] & 0xffl) << 56) |
                   ((buffer[startpos + 1] & 0xffl) << 48) |
                   ((buffer[startpos + 2] & 0xffl) << 40) |
                   ((buffer[startpos + 3] & 0xffl) << 32) |
                   ((buffer[startpos + 4] & 0xffl) << 24) |
                   ((buffer[startpos + 5] & 0xffl) << 16) |
                   ((buffer[startpos + 6] & 0xffl) <<  8) |
                   ((buffer[startpos + 7]) & 0xffl));
        
        return rv;
    }

    private void convertlongtobytearray(long inputlong, byte[] outputarray, int offset)
    {
        for (int i = 0; i < 8; i++)
        {
            outputarray[offset + i] = (byte)((inputlong >> (56 - (i * 8))) & 0xff);
        }
    }

    protected void processblock()
    {
        // buffer contents have been transferred to the _block[] array via
        // processfilledbuffer
        
        // compute and apply k^0
        for (int i = 0; i < 8; i++)
        {
            _state[i] = _block[i] ^ (_k[i] = _hash[i]);
        }

        // iterate over the rounds
        for (int round = 1; round <= rounds; round++)
        {
            for (int i = 0; i < 8; i++)
            {
                _l[i] = 0;
                _l[i] ^= c0[(int)(_k[(i - 0) & 7] >>> 56) & 0xff];
                _l[i] ^= c1[(int)(_k[(i - 1) & 7] >>> 48) & 0xff];
                _l[i] ^= c2[(int)(_k[(i - 2) & 7] >>> 40) & 0xff];
                _l[i] ^= c3[(int)(_k[(i - 3) & 7] >>> 32) & 0xff];
                _l[i] ^= c4[(int)(_k[(i - 4) & 7] >>> 24) & 0xff];
                _l[i] ^= c5[(int)(_k[(i - 5) & 7] >>> 16) & 0xff];
                _l[i] ^= c6[(int)(_k[(i - 6) & 7] >>>  8) & 0xff];
                _l[i] ^= c7[(int)(_k[(i - 7) & 7]) & 0xff];
            }

            system.arraycopy(_l, 0, _k, 0, _k.length);
            
            _k[0] ^= _rc[round];
            
            // apply the round transformation
            for (int i = 0; i < 8; i++)
            {
                _l[i] = _k[i];
                
                _l[i] ^= c0[(int)(_state[(i - 0) & 7] >>> 56) & 0xff];
                _l[i] ^= c1[(int)(_state[(i - 1) & 7] >>> 48) & 0xff];
                _l[i] ^= c2[(int)(_state[(i - 2) & 7] >>> 40) & 0xff];
                _l[i] ^= c3[(int)(_state[(i - 3) & 7] >>> 32) & 0xff];
                _l[i] ^= c4[(int)(_state[(i - 4) & 7] >>> 24) & 0xff];
                _l[i] ^= c5[(int)(_state[(i - 5) & 7] >>> 16) & 0xff];
                _l[i] ^= c6[(int)(_state[(i - 6) & 7] >>> 8) & 0xff];
                _l[i] ^= c7[(int)(_state[(i - 7) & 7]) & 0xff];
            }
            
            // save the current state
            system.arraycopy(_l, 0, _state, 0, _state.length);
        }
        
        // apply miuaguchi-preneel compression
        for (int i = 0; i < 8; i++)
        {
            _hash[i] ^= _state[i] ^ _block[i];
        }
        
    }

    public void update(byte in)
    {
        _buffer[_bufferpos] = in;

        //system.out.println("adding to buffer = "+_buffer[_bufferpos]);
        
        ++_bufferpos;
        
        if (_bufferpos == _buffer.length)
        {
            processfilledbuffer(_buffer, 0);
        }

        increment();
    }

    /*
     * increment() can be implemented in this way using 2 arrays or
     * by having some temporary variables that are used to set the
     * value provided by eight[i] and carry within the loop.
     * 
     * not having done any timing, this seems likely to be faster
     * at the slight expense of 32*(sizeof short) bytes
     */
    private static final short[] eight = new short[bitcount_array_size];
    static 
    {
        eight[bitcount_array_size - 1] = 8;
    }
    
    private void increment()
    {
        int carry = 0;
        for (int i = _bitcount.length - 1; i >= 0; i--)
        {
            int sum = (_bitcount[i] & 0xff) + eight[i] + carry;

            carry = sum >>> 8;
            _bitcount[i] = (short)(sum & 0xff);
        }
    }    
    
    public void update(byte[] in, int inoff, int len)
    {
        while (len > 0)
        {
            update(in[inoff]);
            ++inoff;
            --len;
        }
        
    }
    
    private void finish()
    {
        /*
         * this makes a copy of the current bit length. at the expense of an
         * object creation of 32 bytes rather than providing a _stopcounting
         * boolean which was the alternative i could think of.
         */
        byte[] bitlength = copybitlength(); 
        
        _buffer[_bufferpos++] |= 0x80;

        if (_bufferpos == _buffer.length)
        {
            processfilledbuffer(_buffer, 0);
        }

        /*
         * final block contains 
         * [ ... data .... ][0][0][0][ length ]
         * 
         * if [ length ] cannot fit.  need to create a new block.
         */
        if (_bufferpos > 32)
        {
            while (_bufferpos != 0)
            {
                update((byte)0);
            }
        }
        
        while (_bufferpos <= 32)
        {
            update((byte)0);
        }
        
        // copy the length information to the final 32 bytes of the
        // 64 byte block....
        system.arraycopy(bitlength, 0, _buffer, 32, bitlength.length);
        
        processfilledbuffer(_buffer, 0);
    }

    private byte[] copybitlength()
    {
        byte[] rv = new byte[bitcount_array_size];
        for (int i = 0; i < rv.length; i++)
        {
            rv[i] = (byte)(_bitcount[i] & 0xff);
        }
        return rv;
    }    
    
    public int getbytelength()
    {
        return byte_length;
    }

    public memoable copy()
    {
        return new whirlpooldigest(this);
    }

    public void reset(memoable other)
    {
        whirlpooldigest originaldigest = (whirlpooldigest)other;

        system.arraycopy(originaldigest._rc, 0, _rc, 0, _rc.length);

        system.arraycopy(originaldigest._buffer, 0, _buffer, 0, _buffer.length);

        this._bufferpos = originaldigest._bufferpos;
        system.arraycopy(originaldigest._bitcount, 0, _bitcount, 0, _bitcount.length);

        // -- internal hash state --
        system.arraycopy(originaldigest._hash, 0, _hash, 0, _hash.length);
        system.arraycopy(originaldigest._k, 0, _k, 0, _k.length);
        system.arraycopy(originaldigest._l, 0, _l, 0, _l.length);
        system.arraycopy(originaldigest._block, 0, _block, 0, _block.length);
        system.arraycopy(originaldigest._state, 0, _state, 0, _state.length);
    }
}
