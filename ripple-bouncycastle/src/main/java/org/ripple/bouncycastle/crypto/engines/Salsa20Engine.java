package org.ripple.bouncycastle.crypto.engines;

import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.datalengthexception;
import org.ripple.bouncycastle.crypto.maxbytesexceededexception;
import org.ripple.bouncycastle.crypto.outputlengthexception;
import org.ripple.bouncycastle.crypto.streamcipher;
import org.ripple.bouncycastle.crypto.params.keyparameter;
import org.ripple.bouncycastle.crypto.params.parameterswithiv;
import org.ripple.bouncycastle.crypto.util.pack;
import org.ripple.bouncycastle.util.strings;

/**
 * implementation of daniel j. bernstein's salsa20 stream cipher, snuffle 2005
 */

public class salsa20engine
    implements streamcipher
{
    /** constants */
    private final static int state_size = 16; // 16, 32 bit ints = 64 bytes

    private final static byte[]
        sigma = strings.tobytearray("expand 32-byte k"),
        tau   = strings.tobytearray("expand 16-byte k");

    /*
     * variables to hold the state of the engine
     * during encryption and decryption
     */
    private int         index = 0;
    private int[]       enginestate = new int[state_size]; // state
    private int[]       x = new int[state_size] ; // internal buffer
    private byte[]      keystream   = new byte[state_size * 4], // expanded state, 64 bytes
                        workingkey  = null,
                        workingiv   = null;
    private boolean     initialised = false;

    /*
     * internal counter
     */
    private int cw0, cw1, cw2;

    /**
     * initialise a salsa20 cipher.
     *
     * @param forencryption whether or not we are for encryption.
     * @param params the parameters required to set up the cipher.
     * @exception illegalargumentexception if the params argument is
     * inappropriate.
     */
    public void init(
        boolean             forencryption, 
        cipherparameters     params)
    {
        /* 
        * salsa20 encryption and decryption is completely
        * symmetrical, so the 'forencryption' is 
        * irrelevant. (like 90% of stream ciphers)
        */

        if (!(params instanceof parameterswithiv))
        {
            throw new illegalargumentexception("salsa20 init parameters must include an iv");
        }

        parameterswithiv ivparams = (parameterswithiv) params;

        byte[] iv = ivparams.getiv();

        if (iv == null || iv.length != 8)
        {
            throw new illegalargumentexception("salsa20 requires exactly 8 bytes of iv");
        }

        if (!(ivparams.getparameters() instanceof keyparameter))
        {
            throw new illegalargumentexception("salsa20 init parameters must include a key");
        }

        keyparameter key = (keyparameter) ivparams.getparameters();

        workingkey = key.getkey();
        workingiv = iv;

        setkey(workingkey, workingiv);
    }

    public string getalgorithmname()
    {
        return "salsa20";
    }

    public byte returnbyte(byte in)
    {
        if (limitexceeded())
        {
            throw new maxbytesexceededexception("2^70 byte limit per iv; change iv");
        }

        if (index == 0)
        {
            generatekeystream(keystream);

            if (++enginestate[8] == 0)
            {
                ++enginestate[9];
            }
        }

        byte out = (byte)(keystream[index]^in);
        index = (index + 1) & 63;

        return out;
    }

    public void processbytes(
        byte[]     in, 
        int     inoff, 
        int     len, 
        byte[]     out, 
        int     outoff)
    {
        if (!initialised)
        {
            throw new illegalstateexception(getalgorithmname()+" not initialised");
        }

        if ((inoff + len) > in.length)
        {
            throw new datalengthexception("input buffer too short");
        }

        if ((outoff + len) > out.length)
        {
            throw new outputlengthexception("output buffer too short");
        }

        if (limitexceeded(len))
        {
            throw new maxbytesexceededexception("2^70 byte limit per iv would be exceeded; change iv");
        }

        for (int i = 0; i < len; i++)
        {
            if (index == 0)
            {
                generatekeystream(keystream);

                if (++enginestate[8] == 0)
                {
                    ++enginestate[9];
                }
            }

            out[i+outoff] = (byte)(keystream[index]^in[i+inoff]);
            index = (index + 1) & 63;
        }
    }

    public void reset()
    {
        setkey(workingkey, workingiv);
    }

    // private implementation

    private void setkey(byte[] keybytes, byte[] ivbytes)
    {
        workingkey = keybytes;
        workingiv  = ivbytes;

        index = 0;
        resetcounter();
        int offset = 0;
        byte[] constants;

        // key
        enginestate[1] = pack.littleendiantoint(workingkey, 0);
        enginestate[2] = pack.littleendiantoint(workingkey, 4);
        enginestate[3] = pack.littleendiantoint(workingkey, 8);
        enginestate[4] = pack.littleendiantoint(workingkey, 12);

        if (workingkey.length == 32)
        {
            constants = sigma;
            offset = 16;
        }
        else
        {
            constants = tau;
        }

        enginestate[11] = pack.littleendiantoint(workingkey, offset);
        enginestate[12] = pack.littleendiantoint(workingkey, offset+4);
        enginestate[13] = pack.littleendiantoint(workingkey, offset+8);
        enginestate[14] = pack.littleendiantoint(workingkey, offset+12);
        enginestate[0 ] = pack.littleendiantoint(constants, 0);
        enginestate[5 ] = pack.littleendiantoint(constants, 4);
        enginestate[10] = pack.littleendiantoint(constants, 8);
        enginestate[15] = pack.littleendiantoint(constants, 12);

        // iv
        enginestate[6] = pack.littleendiantoint(workingiv, 0);
        enginestate[7] = pack.littleendiantoint(workingiv, 4);
        enginestate[8] = enginestate[9] = 0;

        initialised = true;
    }

    private void generatekeystream(byte[] output)
    {
        salsacore(20, enginestate, x);
        pack.inttolittleendian(x, output, 0);
    }

    /**
     * salsa20 function
     *
     * @param   input   input data
     *
     * @return  keystream
     */    
    public static void salsacore(int rounds, int[] input, int[] x)
    {
        // todo exception if rounds odd?

        system.arraycopy(input, 0, x, 0, input.length);

        for (int i = rounds; i > 0; i -= 2)
        {
            x[ 4] ^= rotl((x[ 0]+x[12]), 7);
            x[ 8] ^= rotl((x[ 4]+x[ 0]), 9);
            x[12] ^= rotl((x[ 8]+x[ 4]),13);
            x[ 0] ^= rotl((x[12]+x[ 8]),18);
            x[ 9] ^= rotl((x[ 5]+x[ 1]), 7);
            x[13] ^= rotl((x[ 9]+x[ 5]), 9);
            x[ 1] ^= rotl((x[13]+x[ 9]),13);
            x[ 5] ^= rotl((x[ 1]+x[13]),18);
            x[14] ^= rotl((x[10]+x[ 6]), 7);
            x[ 2] ^= rotl((x[14]+x[10]), 9);
            x[ 6] ^= rotl((x[ 2]+x[14]),13);
            x[10] ^= rotl((x[ 6]+x[ 2]),18);
            x[ 3] ^= rotl((x[15]+x[11]), 7);
            x[ 7] ^= rotl((x[ 3]+x[15]), 9);
            x[11] ^= rotl((x[ 7]+x[ 3]),13);
            x[15] ^= rotl((x[11]+x[ 7]),18);
            x[ 1] ^= rotl((x[ 0]+x[ 3]), 7);
            x[ 2] ^= rotl((x[ 1]+x[ 0]), 9);
            x[ 3] ^= rotl((x[ 2]+x[ 1]),13);
            x[ 0] ^= rotl((x[ 3]+x[ 2]),18);
            x[ 6] ^= rotl((x[ 5]+x[ 4]), 7);
            x[ 7] ^= rotl((x[ 6]+x[ 5]), 9);
            x[ 4] ^= rotl((x[ 7]+x[ 6]),13);
            x[ 5] ^= rotl((x[ 4]+x[ 7]),18);
            x[11] ^= rotl((x[10]+x[ 9]), 7);
            x[ 8] ^= rotl((x[11]+x[10]), 9);
            x[ 9] ^= rotl((x[ 8]+x[11]),13);
            x[10] ^= rotl((x[ 9]+x[ 8]),18);
            x[12] ^= rotl((x[15]+x[14]), 7);
            x[13] ^= rotl((x[12]+x[15]), 9);
            x[14] ^= rotl((x[13]+x[12]),13);
            x[15] ^= rotl((x[14]+x[13]),18);
        }

        for (int i = 0; i < state_size; ++i)
        {
            x[i] += input[i];
        }
    }

    /**
     * rotate left
     *
     * @param   x   value to rotate
     * @param   y   amount to rotate x
     *
     * @return  rotated x
     */
    private static int rotl(int x, int y)
    {
        return (x << y) | (x >>> -y);
    }

    private void resetcounter()
    {
        cw0 = 0;
        cw1 = 0;
        cw2 = 0;
    }

    private boolean limitexceeded()
    {
        if (++cw0 == 0)
        {
            if (++cw1 == 0)
            {
                return (++cw2 & 0x20) != 0;          // 2^(32 + 32 + 6)
            }
        }

        return false;
    }

    /*
     * this relies on the fact len will always be positive.
     */
    private boolean limitexceeded(int len)
    {
        cw0 += len;
        if (cw0 < len && cw0 >= 0)
        {
            if (++cw1 == 0)
            {
                return (++cw2 & 0x20) != 0;          // 2^(32 + 32 + 6)
            }
        }

        return false;
    }
}
