package org.ripple.bouncycastle.crypto;

public class ephemeralkeypair
{
    private asymmetriccipherkeypair keypair;
    private keyencoder publickeyencoder;

    public ephemeralkeypair(asymmetriccipherkeypair keypair, keyencoder publickeyencoder)
    {
        this.keypair = keypair;
        this.publickeyencoder = publickeyencoder;
    }

    public asymmetriccipherkeypair getkeypair()
    {
        return keypair;
    }

    public byte[] getencodedpublickey()
    {
        return publickeyencoder.getencoded(keypair.getpublic());
    }
}
