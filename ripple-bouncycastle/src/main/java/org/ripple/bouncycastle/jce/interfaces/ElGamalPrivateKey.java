package org.ripple.bouncycastle.jce.interfaces;

import java.math.biginteger;
import java.security.privatekey;

public interface elgamalprivatekey
    extends elgamalkey, privatekey
{
    public biginteger getx();
}
