package org.ripple.bouncycastle.crypto.engines;

import org.ripple.bouncycastle.crypto.blockcipher;
import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.params.keyparameter;
import org.ripple.bouncycastle.crypto.params.rc5parameters;

/**
 * the specification for rc5 came from the <code>rc5 encryption algorithm</code>
 * publication in rsa cryptobytes, spring of 1995. 
 * <em>http://www.rsasecurity.com/rsalabs/cryptobytes</em>.
 * <p>
 * this implementation has a word size of 32 bits.
 * <p>
 * implementation courtesy of tito pena.
 */
public class rc532engine
    implements blockcipher
{
    /*
     * the number of rounds to perform
     */
    private int _norounds;

    /*
     * the expanded key array of size 2*(rounds + 1)
     */
    private int _s[];

    /*
     * our "magic constants" for 32 32
     *
     * pw = odd((e-2) * 2^wordsize)
     * qw = odd((o-2) * 2^wordsize)
     *
     * where e is the base of natural logarithms (2.718281828...)
     * and o is the golden ratio (1.61803398...)
     */
    private static final int p32 = 0xb7e15163;
    private static final int q32 = 0x9e3779b9;

    private boolean forencryption;

    /**
     * create an instance of the rc5 encryption algorithm
     * and set some defaults
     */
    public rc532engine()
    {
        _norounds     = 12;         // the default
        _s            = null;
    }

    public string getalgorithmname()
    {
        return "rc5-32";
    }

    public int getblocksize()
    {
        return 2 * 4;
    }

    /**
     * initialise a rc5-32 cipher.
     *
     * @param forencryption whether or not we are for encryption.
     * @param params the parameters required to set up the cipher.
     * @exception illegalargumentexception if the params argument is
     * inappropriate.
     */
    public void init(
        boolean             forencryption,
        cipherparameters    params)
    {
        if (params instanceof rc5parameters)
        {
            rc5parameters       p = (rc5parameters)params;

            _norounds     = p.getrounds();

            setkey(p.getkey());
        }
        else if (params instanceof keyparameter)
        {
            keyparameter       p = (keyparameter)params;

            setkey(p.getkey());
        }
        else
        {
            throw new illegalargumentexception("invalid parameter passed to rc532 init - " + params.getclass().getname());
        }

        this.forencryption = forencryption;
    }

    public int processblock(
        byte[]  in,
        int     inoff,
        byte[]  out,
        int     outoff)
    {
        return (forencryption) ? encryptblock(in, inoff, out, outoff) 
                                    : decryptblock(in, inoff, out, outoff);
    }

    public void reset()
    {
    }

    /**
     * re-key the cipher.
     * <p>
     * @param  key  the key to be used
     */
    private void setkey(
        byte[]      key)
    {
        //
        // key expansion:
        //
        // there are 3 phases to the key expansion.
        //
        // phase 1:
        //   copy the secret key k[0...b-1] into an array l[0..c-1] of
        //   c = ceil(b/u), where u = 32/8 in little-endian order.
        //   in other words, we fill up l using u consecutive key bytes
        //   of k. any unfilled byte positions in l are zeroed. in the
        //   case that b = c = 0, set c = 1 and l[0] = 0.
        //
        int[]   l = new int[(key.length + (4 - 1)) / 4];

        for (int i = 0; i != key.length; i++)
        {
            l[i / 4] += (key[i] & 0xff) << (8 * (i % 4));
        }

        //
        // phase 2:
        //   initialize s to a particular fixed pseudo-random bit pattern
        //   using an arithmetic progression modulo 2^wordsize determined
        //   by the magic numbers, pw & qw.
        //
        _s            = new int[2*(_norounds + 1)];

        _s[0] = p32;
        for (int i=1; i < _s.length; i++)
        {
            _s[i] = (_s[i-1] + q32);
        }

        //
        // phase 3:
        //   mix in the user's secret key in 3 passes over the arrays s & l.
        //   the max of the arrays sizes is used as the loop control
        //
        int iter;

        if (l.length > _s.length)
        {
            iter = 3 * l.length;
        }
        else
        {
            iter = 3 * _s.length;
        }

        int a = 0, b = 0;
        int i = 0, j = 0;

        for (int k = 0; k < iter; k++)
        {
            a = _s[i] = rotateleft(_s[i] + a + b, 3);
            b =  l[j] = rotateleft(l[j] + a + b, a+b);
            i = (i+1) % _s.length;
            j = (j+1) %  l.length;
        }
    }

    /**
     * encrypt the given block starting at the given offset and place
     * the result in the provided buffer starting at the given offset.
     * <p>
     * @param  in     in byte buffer containing data to encrypt
     * @param  inoff  offset into src buffer
     * @param  out     out buffer where encrypted data is written
     * @param  outoff  offset into out buffer
     */
    private int encryptblock(
        byte[]  in,
        int     inoff,
        byte[]  out,
        int     outoff)
    {
        int a = bytestoword(in, inoff) + _s[0];
        int b = bytestoword(in, inoff + 4) + _s[1];

        for (int i = 1; i <= _norounds; i++)
        {
            a = rotateleft(a ^ b, b) + _s[2*i];
            b = rotateleft(b ^ a, a) + _s[2*i+1];
        }
        
        wordtobytes(a, out, outoff);
        wordtobytes(b, out, outoff + 4);
        
        return 2 * 4;
    }

    private int decryptblock(
        byte[]  in,
        int     inoff,
        byte[]  out,
        int     outoff)
    {
        int a = bytestoword(in, inoff);
        int b = bytestoword(in, inoff + 4);

        for (int i = _norounds; i >= 1; i--)
        {
            b = rotateright(b - _s[2*i+1], a) ^ a;
            a = rotateright(a - _s[2*i],   b) ^ b;
        }
        
        wordtobytes(a - _s[0], out, outoff);
        wordtobytes(b - _s[1], out, outoff + 4);
        
        return 2 * 4;
    }

    
    //////////////////////////////////////////////////////////////
    //
    // private helper methods
    //
    //////////////////////////////////////////////////////////////

    /**
     * perform a left "spin" of the word. the rotation of the given
     * word <em>x</em> is rotated left by <em>y</em> bits.
     * only the <em>lg(32)</em> low-order bits of <em>y</em>
     * are used to determine the rotation amount. here it is 
     * assumed that the wordsize used is a power of 2.
     * <p>
     * @param  x  word to rotate
     * @param  y    number of bits to rotate % 32
     */
    private int rotateleft(int x, int y)
    {
        return ((x << (y & (32-1))) | (x >>> (32 - (y & (32-1)))));
    }

    /**
     * perform a right "spin" of the word. the rotation of the given
     * word <em>x</em> is rotated left by <em>y</em> bits.
     * only the <em>lg(32)</em> low-order bits of <em>y</em>
     * are used to determine the rotation amount. here it is 
     * assumed that the wordsize used is a power of 2.
     * <p>
     * @param  x  word to rotate
     * @param  y    number of bits to rotate % 32
     */
    private int rotateright(int x, int y)
    {
        return ((x >>> (y & (32-1))) | (x << (32 - (y & (32-1)))));
    }

    private int bytestoword(
        byte[]  src,
        int     srcoff)
    {
        return (src[srcoff] & 0xff) | ((src[srcoff + 1] & 0xff) << 8)
            | ((src[srcoff + 2] & 0xff) << 16) | ((src[srcoff + 3] & 0xff) << 24);
    }

    private void wordtobytes(
        int    word,
        byte[]  dst,
        int     dstoff)
    {
        dst[dstoff] = (byte)word;
        dst[dstoff + 1] = (byte)(word >> 8);
        dst[dstoff + 2] = (byte)(word >> 16);
        dst[dstoff + 3] = (byte)(word >> 24);
    }
}
