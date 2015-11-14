package org.ripple.bouncycastle.crypto.engines;

import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.datalengthexception;
import org.ripple.bouncycastle.crypto.outputlengthexception;
import org.ripple.bouncycastle.crypto.streamcipher;
import org.ripple.bouncycastle.crypto.params.keyparameter;
import org.ripple.bouncycastle.crypto.util.pack;

/**
 * implementation of bob jenkin's isaac (indirection shift accumulate add and count).
 * see: http://www.burtleburtle.net/bob/rand/isaacafa.html
*/
public class isaacengine
    implements streamcipher
{
    // constants
    private final int sizel          = 8,
                      statearraysize = sizel<<5; // 256
    
    // cipher's internal state
    private int[]   enginestate   = null, // mm                
                    results       = null; // randrsl
    private int     a = 0, b = 0, c = 0;
    
    // engine state
    private int     index         = 0;
    private byte[]  keystream     = new byte[statearraysize<<2], // results expanded into bytes
                    workingkey    = null;
    private boolean initialised   = false;
    
    /**
     * initialise an isaac cipher.
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
            throw new illegalargumentexception("invalid parameter passed to isaac init - " + params.getclass().getname());
        }
        /* 
         * isaac encryption and decryption is completely
         * symmetrical, so the 'forencryption' is 
         * irrelevant.
         */
        keyparameter p = (keyparameter)params;
        setkey(p.getkey());
        
        return;
    }
                    
    public byte returnbyte(byte in)
    {
        if (index == 0) 
        {
            isaac();
            keystream = pack.inttobigendian(results);
        }
        byte out = (byte)(keystream[index]^in);
        index = (index + 1) & 1023;
        
        return out;
    }
    
    public void processbytes(
        byte[]  in, 
        int     inoff, 
        int     len, 
        byte[]  out, 
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
        
        for (int i = 0; i < len; i++)
        {
            if (index == 0) 
            {
                isaac();
                keystream = pack.inttobigendian(results);
            }
            out[i+outoff] = (byte)(keystream[index]^in[i+inoff]);
            index = (index + 1) & 1023;
        }
    }
    
    public string getalgorithmname()
    {
        return "isaac";
    }
    
    public void reset()
    {
        setkey(workingkey);
    }
    
    // private implementation
    private void setkey(byte[] keybytes)
    {
        workingkey = keybytes;
        
        if (enginestate == null)
        {
            enginestate = new int[statearraysize];
        }
        
        if (results == null)
        {
            results = new int[statearraysize];
        }
        
        int i, j, k;
        
        // reset state
        for (i = 0; i < statearraysize; i++)
        {
            enginestate[i] = results[i] = 0;
        }
        a = b = c = 0;
        
        // reset index counter for output
        index = 0;
        
        // convert the key bytes to ints and put them into results[] for initialization
        byte[] t = new byte[keybytes.length + (keybytes.length & 3)];
        system.arraycopy(keybytes, 0, t, 0, keybytes.length);
        for (i = 0; i < t.length; i+=4)
        {
            results[i >>> 2] = pack.littleendiantoint(t, i);
        }

        // it has begun?
        int[] abcdefgh = new int[sizel];
        
        for (i = 0; i < sizel; i++)
        {
            abcdefgh[i] = 0x9e3779b9; // phi (golden ratio)
        }
        
        for (i = 0; i < 4; i++)
        {
            mix(abcdefgh);
        }
        
        for (i = 0; i < 2; i++)
        {
            for (j = 0; j < statearraysize; j+=sizel)
            {
                for (k = 0; k < sizel; k++)
                {
                    abcdefgh[k] += (i<1) ? results[j+k] : enginestate[j+k];
                }
                
                mix(abcdefgh);
                
                for (k = 0; k < sizel; k++)
                {
                    enginestate[j+k] = abcdefgh[k];
                }
            }
        }
        
        isaac();
        
        initialised = true;
    }    
    
    private void isaac()
    {
        int i, x, y;
        
        b += ++c;
        for (i = 0; i < statearraysize; i++)
        {
            x = enginestate[i];
            switch (i & 3)
            {
                case 0: a ^= (a <<  13); break;
                case 1: a ^= (a >>>  6); break;
                case 2: a ^= (a <<   2); break;
                case 3: a ^= (a >>> 16); break;
            }
            a += enginestate[(i+128) & 0xff];
            enginestate[i] = y = enginestate[(x >>> 2) & 0xff] + a + b;
            results[i] = b = enginestate[(y >>> 10) & 0xff] + x;
        }
    }
    
    private void mix(int[] x)
    {
        x[0]^=x[1]<< 11; x[3]+=x[0]; x[1]+=x[2];
        x[1]^=x[2]>>> 2; x[4]+=x[1]; x[2]+=x[3];
        x[2]^=x[3]<<  8; x[5]+=x[2]; x[3]+=x[4];
        x[3]^=x[4]>>>16; x[6]+=x[3]; x[4]+=x[5];
        x[4]^=x[5]<< 10; x[7]+=x[4]; x[5]+=x[6];
        x[5]^=x[6]>>> 4; x[0]+=x[5]; x[6]+=x[7];
        x[6]^=x[7]<<  8; x[1]+=x[6]; x[7]+=x[0];
        x[7]^=x[0]>>> 9; x[2]+=x[7]; x[0]+=x[1];
    }
}
