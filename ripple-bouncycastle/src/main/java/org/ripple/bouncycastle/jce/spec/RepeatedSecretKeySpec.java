package org.ripple.bouncycastle.jce.spec;


import javax.crypto.secretkey;

/**
 * a simple object to indicate that a symmetric cipher should reuse the
 * last key provided.
 */
public class repeatedsecretkeyspec
    implements secretkey
{
    private string algorithm;

    public repeatedsecretkeyspec(string algorithm)
    {
        this.algorithm = algorithm;
    }

    public string getalgorithm()
    {
        return algorithm;
    }

    public string getformat()
    {
        return null;
    }

    public byte[] getencoded()
    {
        return null;
    }
}
