package org.ripple.bouncycastle.jcajce.provider.keystore;

import org.ripple.bouncycastle.jcajce.provider.config.configurableprovider;
import org.ripple.bouncycastle.jcajce.provider.util.asymmetricalgorithmprovider;

public class pkcs12
{
    private static final string prefix = "org.bouncycastle.jcajce.provider.keystore" + ".pkcs12.";

    public static class mappings
        extends asymmetricalgorithmprovider
    {
        public mappings()
        {
        }
        
        public void configure(configurableprovider provider)
        {
            provider.addalgorithm("keystore.pkcs12", prefix + "pkcs12keystorespi$bcpkcs12keystore");
            provider.addalgorithm("keystore.bcpkcs12", prefix + "pkcs12keystorespi$bcpkcs12keystore");
            provider.addalgorithm("keystore.pkcs12-def", prefix + "pkcs12keystorespi$defpkcs12keystore");

            provider.addalgorithm("keystore.pkcs12-3des-40rc2", prefix + "pkcs12keystorespi$bcpkcs12keystore");
            provider.addalgorithm("keystore.pkcs12-3des-3des", prefix + "pkcs12keystorespi$bcpkcs12keystore3des");
    
            provider.addalgorithm("keystore.pkcs12-def-3des-40rc2", prefix + "pkcs12keystorespi$defpkcs12keystore");
            provider.addalgorithm("keystore.pkcs12-def-3des-3des", prefix + "pkcs12keystorespi$defpkcs12keystore3des");
        }
    }
}
