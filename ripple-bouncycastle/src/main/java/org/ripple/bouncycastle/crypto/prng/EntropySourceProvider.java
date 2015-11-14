package org.ripple.bouncycastle.crypto.prng;

public interface entropysourceprovider
{
    entropysource get(final int bitsrequired);
}
