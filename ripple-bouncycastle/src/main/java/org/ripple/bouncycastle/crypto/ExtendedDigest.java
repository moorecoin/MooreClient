package org.ripple.bouncycastle.crypto;

public interface extendeddigest 
    extends digest
{
    /**
     * return the size in bytes of the internal buffer the digest applies it's compression
     * function to.
     * 
     * @return byte length of the digests internal buffer.
     */
    public int getbytelength();
}
