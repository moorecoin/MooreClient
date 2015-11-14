package org.ripple.bouncycastle.jce.interfaces;

import java.math.biginteger;

public interface gost3410privatekey extends gost3410key, java.security.privatekey
{

    public biginteger getx();
}
