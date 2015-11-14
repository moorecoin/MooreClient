package org.ripple.bouncycastle.crypto.digests;

import org.ripple.bouncycastle.crypto.extendeddigest;

/**
 * wrapper class that reduces the output length of a particular digest to
 * only the first n bytes of the digest function.
 */
public class shorteneddigest 
    implements extendeddigest
{
    private extendeddigest basedigest;
    private int            length;
    
    /**
     * base constructor.
     * 
     * @param basedigest underlying digest to use.
     * @param length length in bytes of the output of dofinal.
     * @exception illegalargumentexception if basedigest is null, or length is greater than basedigest.getdigestsize().
     */
    public shorteneddigest(
        extendeddigest basedigest,
        int            length)
    {
        if (basedigest == null)
        {
            throw new illegalargumentexception("basedigest must not be null");
        }
        
        if (length > basedigest.getdigestsize())
        {
            throw new illegalargumentexception("basedigest output not large enough to support length");
        }
        
        this.basedigest = basedigest;
        this.length = length;
    }
    
    public string getalgorithmname()
    {
        return basedigest.getalgorithmname() + "(" + length * 8 + ")";
    }

    public int getdigestsize()
    {
        return length;
    }

    public void update(byte in)
    {
        basedigest.update(in);
    }

    public void update(byte[] in, int inoff, int len)
    {
        basedigest.update(in, inoff, len);
    }

    public int dofinal(byte[] out, int outoff)
    {
        byte[] tmp = new byte[basedigest.getdigestsize()];
        
        basedigest.dofinal(tmp, 0);
        
        system.arraycopy(tmp, 0, out, outoff, length);
        
        return length;
    }

    public void reset()
    {
        basedigest.reset();
    }

    public int getbytelength()
    {
        return basedigest.getbytelength();
    }
}
