package org.ripple.bouncycastle.bcpg;

import java.io.datainputstream;
import java.io.ioexception;
import java.io.inputstream;

/**
 * the string to key specifier class
 */
public class s2k 
    extends bcpgobject
{
    private static final int expbias = 6;
    
    public static final int simple = 0;
    public static final int salted = 1;
    public static final int salted_and_iterated = 3;
    public static final int gnu_dummy_s2k = 101;
    
    int       type;
    int       algorithm;
    byte[]    iv;
    int       itcount = -1;
    int       protectionmode = -1;
    
    s2k(
        inputstream    in)
        throws ioexception
    {
        datainputstream    din = new datainputstream(in);
        
        type = din.read();
        algorithm = din.read();
        
        //
        // if this happens we have a dummy-s2k packet.
        //
        if (type != gnu_dummy_s2k)
        {
            if (type != 0)
            {
                iv = new byte[8];
                din.readfully(iv, 0, iv.length);

                if (type == 3)
                {
                    itcount = din.read();
                }
            }
        }
        else
        {
            din.read(); // g
            din.read(); // n
            din.read(); // u
            protectionmode = din.read(); // protection mode
        }
    }
    
    public s2k(
        int        algorithm)
    {
        this.type = 0;
        this.algorithm = algorithm;
    }
    
    public s2k(
        int        algorithm,
        byte[]    iv)
    {
        this.type = 1;
        this.algorithm = algorithm;
        this.iv = iv;
    }

    public s2k(
        int       algorithm,
        byte[]    iv,
        int       itcount)
    {
        this.type = 3;
        this.algorithm = algorithm;
        this.iv = iv;
        this.itcount = itcount;
    }
    
    public int gettype()
    {
        return type;
    }
    
    /**
     * return the hash algorithm for this s2k
     */
    public int gethashalgorithm()
    {
        return algorithm;
    }
    
    /**
     * return the iv for the key generation algorithm
     */
    public byte[] getiv()
    {
        return iv;
    }
    
    /**
     * return the iteration count
     */
    public long getiterationcount()
    {
        return (16 + (itcount & 15)) << ((itcount >> 4) + expbias);
    }
    
    /**
     * the protection mode - only if gnu_dummy_s2k
     */
    public int getprotectionmode()
    {
        return protectionmode;
    }
    
    public void encode(
        bcpgoutputstream    out)
        throws ioexception
    {
        out.write(type);
        out.write(algorithm);
    
        if (type != gnu_dummy_s2k)
        {
            if (type != 0)
            {
                out.write(iv);
            }
            
            if (type == 3)
            {
                out.write(itcount);
            }
        }
        else
        {
            out.write('g');
            out.write('n');
            out.write('u');
            out.write(protectionmode);
        }
    }
}
