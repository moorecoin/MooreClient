package org.ripple.bouncycastle.crypto.paddings;

import java.security.securerandom;

import org.ripple.bouncycastle.crypto.invalidciphertextexception;

/**
 * a padder that adds the padding according to the scheme referenced in
 * iso 7814-4 - scheme 2 from iso 9797-1. the first byte is 0x80, rest is 0x00
 */
public class iso7816d4padding
    implements blockcipherpadding
{
    /**
     * initialise the padder.
     *
     * @param random - a securerandom if available.
     */
    public void init(securerandom random)
        throws illegalargumentexception
    {
        // nothing to do.
    }

    /**
     * return the name of the algorithm the padder implements.
     *
     * @return the name of the algorithm the padder implements.
     */
    public string getpaddingname()
    {
        return "iso7816-4";
    }

    /**
     * add the pad bytes to the passed in block, returning the
     * number of bytes added.
     */
    public int addpadding(
        byte[]  in,
        int     inoff)
    {
        int added = (in.length - inoff);

        in [inoff]= (byte) 0x80;
        inoff ++;
        
        while (inoff < in.length)
        {
            in[inoff] = (byte) 0;
            inoff++;
        }

        return added;
    }

    /**
     * return the number of pad bytes present in the block.
     */
    public int padcount(byte[] in)
        throws invalidciphertextexception
    {
        int count = in.length - 1;

        while (count > 0 && in[count] == 0)
        {
            count--;
        }

        if (in[count] != (byte)0x80)
        {
            throw new invalidciphertextexception("pad block corrupted");
        }
        
        return in.length - count;
    }
}
