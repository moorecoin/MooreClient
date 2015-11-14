package org.ripple.bouncycastle.jce.interfaces;

import java.math.biginteger;
import java.security.publickey;

public interface elgamalpublickey
    extends elgamalkey, publickey
{
    public biginteger gety();
}
