package org.ripple.bouncycastle.crypto.tls;

public class securityparameters
{

    int entity = -1;
    int prfalgorithm = -1;
    short compressionalgorithm = -1;
    int verifydatalength = -1;
    byte[] mastersecret = null;
    byte[] clientrandom = null;
    byte[] serverrandom = null;

    /**
     * @return {@link connectionend}
     */
    public int getentity()
    {
        return entity;
    }

    /**
     * @return {@link prfalgorithm}
     */
    public int getprfalgorithm()
    {
        return prfalgorithm;
    }

    /**
     * @return {@link compressionmethod}
     */
    public short getcompressionalgorithm()
    {
        return compressionalgorithm;
    }

    public int getverifydatalength()
    {
        return verifydatalength;
    }

    public byte[] getmastersecret()
    {
        return mastersecret;
    }

    public byte[] getclientrandom()
    {
        return clientrandom;
    }

    public byte[] getserverrandom()
    {
        return serverrandom;
    }
}
