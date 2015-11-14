package org.ripple.bouncycastle.crypto.digests;

import org.ripple.bouncycastle.crypto.extendeddigest;

/**
 * wrapper removes exposure to the memoable interface on an extendeddigest implementation.
 */
public class nonmemoabledigest
    implements extendeddigest
{
    private extendeddigest basedigest;

    /**
     * base constructor.
     *
     * @param basedigest underlying digest to use.
     * @exception illegalargumentexception if basedigest is null
     */
    public nonmemoabledigest(
        extendeddigest basedigest)
    {
        if (basedigest == null)
        {
            throw new illegalargumentexception("basedigest must not be null");
        }

        this.basedigest = basedigest;
    }
    
    public string getalgorithmname()
    {
        return basedigest.getalgorithmname();
    }

    public int getdigestsize()
    {
        return basedigest.getdigestsize();
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
        return basedigest.dofinal(out, outoff);
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
