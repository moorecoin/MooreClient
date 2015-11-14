package org.ripple.bouncycastle.jcajce.provider.asymmetric.util;

import org.ripple.bouncycastle.crypto.engines.iesengine;
import org.ripple.bouncycastle.jce.spec.iesparameterspec;

public class iesutil
{
    public static iesparameterspec guessparameterspec(iesengine engine)
    {
        if (engine.getcipher() == null)
        {
            return new iesparameterspec(null, null, 128);
        }
        else if (engine.getcipher().getunderlyingcipher().getalgorithmname().equals("des") ||
                engine.getcipher().getunderlyingcipher().getalgorithmname().equals("rc2") ||
                engine.getcipher().getunderlyingcipher().getalgorithmname().equals("rc5-32") ||
                engine.getcipher().getunderlyingcipher().getalgorithmname().equals("rc5-64"))
        {
            return new iesparameterspec(null, null, 64, 64);
        }
        else if (engine.getcipher().getunderlyingcipher().getalgorithmname().equals("skipjack"))
        {
            return new iesparameterspec(null, null, 80, 80);
        }
        else if (engine.getcipher().getunderlyingcipher().getalgorithmname().equals("gost28147"))
        {
            return new iesparameterspec(null, null, 256, 256);
        }

        return new iesparameterspec(null, null, 128, 128);
    }
}
