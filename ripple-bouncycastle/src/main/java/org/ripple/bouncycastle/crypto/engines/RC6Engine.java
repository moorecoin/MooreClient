package org.ripple.bouncycastle.crypto.engines;

import org.ripple.bouncycastle.crypto.blockcipher;
import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.datalengthexception;
import org.ripple.bouncycastle.crypto.outputlengthexception;
import org.ripple.bouncycastle.crypto.params.keyparameter;

/**
 * an rc6 engine.
 */
public class rc6engine
    implements blockcipher
{
    private static final int wordsize = 32;
    private static final int bytesperword = wordsize / 8;

    /*
     * the number of rounds to perform
     */
    private static final int _norounds = 20;

    /*
     * the expanded key array of size 2*(rounds + 1)
     */
    private int _s[];

    /*
     * our "magic constants" for wordsize 32
     *
     * pw = odd((e-2) * 2^wordsize)
     * qw = odd((o-2) * 2^wordsize)
     *
     * where e is the base of natural logarithms (2.718281828...)
     * and o is the golden ratio (1.61803398...)
     */
    private static final int    p32 = 0xb7e15163;
    private static final int    q32 = 0x9e3779b9;

    private static final int    lgw = 5;        // log2(32)

    private boolean forencryption;

    /**
     * create an instance of the rc6 encryption algorithm
     * and set some defaults
     */
    public rc6engine()
    {
        _s            = null;
    }

    public string getalgorithmname()
    {
        return "rc6";
    }

    public int getblocksize()
    {
        return 4 * bytesperword;
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
        if (!(params instanceof keyparameter))
        {
            throw new illegalargumentexception("invalid parameter passed to rc6 init - " + params.getclass().getname());
        }

        keyparameter       p = (keyparameter)params;
        this.forencryption = forencryption;
        setkey(p.getkey());
    }

    public int processblock(
        byte[]  in,
        int     inoff,
        byte[]  out,
        int     outoff)
    {
        int blocksize = getblocksize();
        if (_s == null)
        {
            throw new illegalstateexception("rc6 engine not initialised");
        }
        if ((inoff + blocksize) > in.length)
        {
            throw new datalengthexception("input buffer too short");
        }
        if ((outoff + blocksize) > out.length)
        {
            throw new outputlengthexception("output buffer too short");
        }

        return (forencryption)
            ?   encryptblock(in, inoff, out, outoff) 
            :   decryptblock(in, inoff, out, outoff);
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
        //   c = ceil(b/u), where u = wordsize/8 in little-endian order.
        //   in other words, we fill up l using u consecutive key bytes
        //   of k. any unfilled byte positions in l are zeroed. in the
        //   case that b = c = 0, set c = 1 and l[0] = 0.
        //
        // compute number of dwords
        int c = (key.length + (bytesperword - 1)) / bytesperword;
        if (c == 0)
        {
            c = 1;
        }
        int[]   l = new int[(key.length + bytesperword - 1) / bytesperword];

        // load all key bytes into array of key dwords
        for (int i = key.length - 1; i >= 0; i--)
        {
            l[i / bytesperword] = (l[i / bytesperword] << 8) + (key[i] & 0xff);
        }

        //
        // phase 2:
        //   key schedule is placed in a array of 2+2*rounds+2 = 44 dwords.
        //   initialize s to a particular fixed pseudo-random bit pattern
        //   using an arithmetic progression modulo 2^wordsize determined
        //   by the magic numbers, pw & qw.
        //
        _s            = new int[2+2*_norounds+2];

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

        int a = 0;
        int b = 0;
        int i = 0, j = 0;

        for (int k = 0; k < iter; k++)
        {
            a = _s[i] = rotateleft(_s[i] + a + b, 3);
            b =  l[j] = rotateleft(l[j] + a + b, a+b);
            i = (i+1) % _s.length;
            j = (j+1) %  l.length;
        }
    }

    private int encryptblock(
        byte[]  in,
        int     inoff,
        byte[]  out,
        int     outoff)
    {
        // load a,b,c and d registers from in.
        int a = bytestoword(in, inoff);
        int b = bytestoword(in, inoff + bytesperword);
        int c = bytestoword(in, inoff + bytesperword*2);
        int d = bytestoword(in, inoff + bytesperword*3);
        
        // do pseudo-round #0: pre-whitening of b and d
        b += _s[0];
        d += _s[1];

        // perform round #1,#2 ... #rounds of encryption 
        for (int i = 1; i <= _norounds; i++)
        {
            int t = 0,u = 0;
            
            t = b*(2*b+1);
            t = rotateleft(t,5);
            
            u = d*(2*d+1);
            u = rotateleft(u,5);
            
            a ^= t;
            a = rotateleft(a,u);
            a += _s[2*i];
            
            c ^= u;
            c = rotateleft(c,t);
            c += _s[2*i+1];
            
            int temp = a;
            a = b;
            b = c;
            c = d;
            d = temp;            
        }
        // do pseudo-round #(rounds+1) : post-whitening of a and c
        a += _s[2*_norounds+2];
        c += _s[2*_norounds+3];
            
        // store a, b, c and d registers to out        
        wordtobytes(a, out, outoff);
        wordtobytes(b, out, outoff + bytesperword);
        wordtobytes(c, out, outoff + bytesperword*2);
        wordtobytes(d, out, outoff + bytesperword*3);
        
        return 4 * bytesperword;
    }

    private int decryptblock(
        byte[]  in,
        int     inoff,
        byte[]  out,
        int     outoff)
    {
        // load a,b,c and d registers from out.
        int a = bytestoword(in, inoff);
        int b = bytestoword(in, inoff + bytesperword);
        int c = bytestoword(in, inoff + bytesperword*2);
        int d = bytestoword(in, inoff + bytesperword*3);

        // undo pseudo-round #(rounds+1) : post whitening of a and c 
        c -= _s[2*_norounds+3];
        a -= _s[2*_norounds+2];
        
        // undo round #rounds, .., #2,#1 of encryption 
        for (int i = _norounds; i >= 1; i--)
        {
            int t=0,u = 0;
            
            int temp = d;
            d = c;
            c = b;
            b = a;
            a = temp;
            
            t = b*(2*b+1);
            t = rotateleft(t, lgw);
            
            u = d*(2*d+1);
            u = rotateleft(u, lgw);
            
            c -= _s[2*i+1];
            c = rotateright(c,t);
            c ^= u;
            
            a -= _s[2*i];
            a = rotateright(a,u);
            a ^= t;
            
        }
        // undo pseudo-round #0: pre-whitening of b and d
        d -= _s[1];
        b -= _s[0];
        
        wordtobytes(a, out, outoff);
        wordtobytes(b, out, outoff + bytesperword);
        wordtobytes(c, out, outoff + bytesperword*2);
        wordtobytes(d, out, outoff + bytesperword*3);
        
        return 4 * bytesperword;
    }

    
    //////////////////////////////////////////////////////////////
    //
    // private helper methods
    //
    //////////////////////////////////////////////////////////////

    /**
     * perform a left "spin" of the word. the rotation of the given
     * word <em>x</em> is rotated left by <em>y</em> bits.
     * only the <em>lg(wordsize)</em> low-order bits of <em>y</em>
     * are used to determine the rotation amount. here it is 
     * assumed that the wordsize used is 32.
     * <p>
     * @param  x  word to rotate
     * @param  y    number of bits to rotate % wordsize
     */
    private int rotateleft(int x, int y)
    {
        return (x << y) | (x >>> -y);
    }

    /**
     * perform a right "spin" of the word. the rotation of the given
     * word <em>x</em> is rotated left by <em>y</em> bits.
     * only the <em>lg(wordsize)</em> low-order bits of <em>y</em>
     * are used to determine the rotation amount. here it is 
     * assumed that the wordsize used is a power of 2.
     * <p>
     * @param  x  word to rotate
     * @param  y    number of bits to rotate % wordsize
     */
    private int rotateright(int x, int y)
    {
        return (x >>> y) | (x << -y);
    }

    private int bytestoword(
        byte[]  src,
        int     srcoff)
    {
        int    word = 0;

        for (int i = bytesperword - 1; i >= 0; i--)
        {
            word = (word << 8) + (src[i + srcoff] & 0xff);
        }

        return word;
    }

    private void wordtobytes(
        int    word,
        byte[]  dst,
        int     dstoff)
    {
        for (int i = 0; i < bytesperword; i++)
        {
            dst[i + dstoff] = (byte)word;
            word >>>= 8;
        }
    }
}
