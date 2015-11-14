package org.ripple.bouncycastle.crypto.engines;

import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.datalengthexception;
import org.ripple.bouncycastle.crypto.outputlengthexception;
import org.ripple.bouncycastle.crypto.streamcipher;
import org.ripple.bouncycastle.crypto.params.keyparameter;

public class rc4engine implements streamcipher
{
    private final static int state_length = 256;

    /*
     * variables to hold the state of the rc4 engine
     * during encryption and decryption
     */

    private byte[]      enginestate = null;
    private int         x = 0;
    private int         y = 0;
    private byte[]      workingkey = null;

    /**
     * initialise a rc4 cipher.
     *
     * @param forencryption whether or not we are for encryption.
     * @param params the parameters required to set up the cipher.
     * @exception illegalargumentexception if the params argument is
     * inappropriate.
     */
    public void init(
        boolean             forencryption, 
        cipherparameters     params
   )
    {
        if (params instanceof keyparameter)
        {
            /* 
             * rc4 encryption and decryption is completely
             * symmetrical, so the 'forencryption' is 
             * irrelevant.
             */
            workingkey = ((keyparameter)params).getkey();
            setkey(workingkey);

            return;
        }

        throw new illegalargumentexception("invalid parameter passed to rc4 init - " + params.getclass().getname());
    }

    public string getalgorithmname()
    {
        return "rc4";
    }

    public byte returnbyte(byte in)
    {
        x = (x + 1) & 0xff;
        y = (enginestate[x] + y) & 0xff;

        // swap
        byte tmp = enginestate[x];
        enginestate[x] = enginestate[y];
        enginestate[y] = tmp;

        // xor
        return (byte)(in ^ enginestate[(enginestate[x] + enginestate[y]) & 0xff]);
    }

    public void processbytes(
        byte[]     in, 
        int     inoff, 
        int     len, 
        byte[]     out, 
        int     outoff)
    {
        if ((inoff + len) > in.length)
        {
            throw new datalengthexception("input buffer too short");
        }

        if ((outoff + len) > out.length)
        {
            throw new outputlengthexception("output buffer too short");
        }

        for (int i = 0; i < len ; i++)
        {
            x = (x + 1) & 0xff;
            y = (enginestate[x] + y) & 0xff;

            // swap
            byte tmp = enginestate[x];
            enginestate[x] = enginestate[y];
            enginestate[y] = tmp;

            // xor
            out[i+outoff] = (byte)(in[i + inoff]
                    ^ enginestate[(enginestate[x] + enginestate[y]) & 0xff]);
        }
    }

    public void reset()
    {
        setkey(workingkey);
    }

    // private implementation

    private void setkey(byte[] keybytes)
    {
        workingkey = keybytes;

        // system.out.println("the key length is ; "+ workingkey.length);

        x = 0;
        y = 0;

        if (enginestate == null)
        {
            enginestate = new byte[state_length];
        }

        // reset the state of the engine
        for (int i=0; i < state_length; i++)
        {
            enginestate[i] = (byte)i;
        }
        
        int i1 = 0;
        int i2 = 0;

        for (int i=0; i < state_length; i++)
        {
            i2 = ((keybytes[i1] & 0xff) + enginestate[i] + i2) & 0xff;
            // do the byte-swap inline
            byte tmp = enginestate[i];
            enginestate[i] = enginestate[i2];
            enginestate[i2] = tmp;
            i1 = (i1+1) % keybytes.length; 
        }
    }
}
