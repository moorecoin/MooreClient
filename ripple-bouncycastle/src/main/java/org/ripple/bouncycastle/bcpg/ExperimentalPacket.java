package org.ripple.bouncycastle.bcpg;

import java.io.ioexception;

import org.ripple.bouncycastle.util.arrays;

/**
 * basic packet for an experimental packet.
 */
public class experimentalpacket 
    extends containedpacket implements publickeyalgorithmtags
{
    private int    tag;
    private byte[] contents;
    
    /**
     * 
     * @param in
     * @throws ioexception
     */
    experimentalpacket(
        int                tag,
        bcpginputstream    in)
        throws ioexception
    {
        this.tag = tag;
        this.contents = in.readall();
    }

    public int gettag()
    {
        return tag;
    }
    
    public byte[] getcontents()
    {
        return arrays.clone(contents);
    }

    public void encode(
        bcpgoutputstream    out)
        throws ioexception
    {
        out.writepacket(tag, contents, true);
    }
}
