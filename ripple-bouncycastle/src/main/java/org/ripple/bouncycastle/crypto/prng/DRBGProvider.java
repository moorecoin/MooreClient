package org.ripple.bouncycastle.crypto.prng;

import org.ripple.bouncycastle.crypto.prng.drbg.sp80090drbg;

interface drbgprovider
{
    sp80090drbg get(entropysource entropysource);
}
