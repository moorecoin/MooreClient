package org.ripple.bouncycastle.crypto.generators;

import org.ripple.bouncycastle.crypto.asymmetriccipherkeypair;
import org.ripple.bouncycastle.crypto.asymmetriccipherkeypairgenerator;
import org.ripple.bouncycastle.crypto.ephemeralkeypair;
import org.ripple.bouncycastle.crypto.keyencoder;

public class ephemeralkeypairgenerator
{
    private asymmetriccipherkeypairgenerator gen;
    private keyencoder keyencoder;

    public ephemeralkeypairgenerator(asymmetriccipherkeypairgenerator gen, keyencoder keyencoder)
    {
        this.gen = gen;
        this.keyencoder = keyencoder;
    }

    public ephemeralkeypair generate()
    {
        asymmetriccipherkeypair eph = gen.generatekeypair();

        // encode the ephemeral public key
         return new ephemeralkeypair(eph, keyencoder);
    }
}
