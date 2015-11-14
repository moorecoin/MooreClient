package org.ripple.bouncycastle.jce.spec; 

import java.security.spec.algorithmparameterspec;

import org.ripple.bouncycastle.crypto.engines.gost28147engine;

/**
 * a parameter spec for the gost-28147 cipher.
 */
public class gost28147parameterspec
    implements algorithmparameterspec
{
    private byte[] iv = null;
    private byte[] sbox = null;

    public gost28147parameterspec(
        byte[] sbox)
    {
        this.sbox = new byte[sbox.length];
        
        system.arraycopy(sbox, 0, this.sbox, 0, sbox.length);
    }

    public gost28147parameterspec(
        byte[] sbox,
        byte[] iv)
    {
        this(sbox);
        this.iv = new byte[iv.length];
        
        system.arraycopy(iv, 0, this.iv, 0, iv.length);
    }
    
    public gost28147parameterspec(
        string  sboxname)
    {
        this.sbox = gost28147engine.getsbox(sboxname);
    }

    public gost28147parameterspec(
        string  sboxname,
        byte[]  iv)
    {
        this(sboxname);
        this.iv = new byte[iv.length];
        
        system.arraycopy(iv, 0, this.iv, 0, iv.length);
    }

    public byte[] getsbox()
    {
        return sbox;
    }

    /**
     * returns the iv or null if this parameter set does not contain an iv.
     *
     * @return the iv or null if this parameter set does not contain an iv.
     */
    public byte[] getiv()
    {
        if (iv == null)
        {
            return null;
        }

        byte[]  tmp = new byte[iv.length];

        system.arraycopy(iv, 0, tmp, 0, tmp.length);

        return tmp;
    }
}