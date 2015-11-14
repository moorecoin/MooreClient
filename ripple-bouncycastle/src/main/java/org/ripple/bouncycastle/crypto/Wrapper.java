package org.ripple.bouncycastle.crypto;

public interface wrapper
{
    public void init(boolean forwrapping, cipherparameters param);

    /**
     * return the name of the algorithm the wrapper implements.
     *
     * @return the name of the algorithm the wrapper implements.
     */
    public string getalgorithmname();

    public byte[] wrap(byte[] in, int inoff, int inlen);

    public byte[] unwrap(byte[] in, int inoff, int inlen)
        throws invalidciphertextexception;
}
