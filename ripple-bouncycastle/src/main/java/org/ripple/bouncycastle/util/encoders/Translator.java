package org.ripple.bouncycastle.util.encoders;

/**
 * general interface for an translator.
 */
public interface translator
{
    /**
     * size of the output block on encoding produced by getdecodedblocksize()
     * bytes.
     */
    public int getencodedblocksize();

    public int encode(byte[] in, int inoff, int length, byte[] out, int outoff);

    /**
     * size of the output block on decoding produced by getencodedblocksize()
     * bytes.
     */
    public int getdecodedblocksize();

    public int decode(byte[] in, int inoff, int length, byte[] out, int outoff);
}
