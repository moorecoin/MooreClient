package org.ripple.bouncycastle.jce.interfaces;

import java.security.publickey;
import java.math.biginteger;

public interface gost3410publickey extends gost3410key, publickey
{

    public biginteger gety();
}
