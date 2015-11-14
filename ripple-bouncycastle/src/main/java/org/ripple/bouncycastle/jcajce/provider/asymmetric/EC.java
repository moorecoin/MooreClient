package org.ripple.bouncycastle.jcajce.provider.asymmetric;

import org.ripple.bouncycastle.asn1.eac.eacobjectidentifiers;
import org.ripple.bouncycastle.asn1.teletrust.teletrustobjectidentifiers;
import org.ripple.bouncycastle.asn1.x9.x9objectidentifiers;
import org.ripple.bouncycastle.jcajce.provider.asymmetric.ec.keyfactoryspi;
import org.ripple.bouncycastle.jcajce.provider.config.configurableprovider;
import org.ripple.bouncycastle.jcajce.provider.util.asymmetricalgorithmprovider;

public class ec
{
    private static final string prefix = "org.bouncycastle.jcajce.provider.asymmetric" + ".ec.";

    public static class mappings
        extends asymmetricalgorithmprovider
    {
        public mappings()
        {
        }

        public void configure(configurableprovider provider)
        {
            provider.addalgorithm("keyagreement.ecdh", prefix + "keyagreementspi$dh");
            provider.addalgorithm("keyagreement.ecdhc", prefix + "keyagreementspi$dhc");
            provider.addalgorithm("keyagreement.ecmqv", prefix + "keyagreementspi$mqv");
            provider.addalgorithm("keyagreement." + x9objectidentifiers.dhsinglepass_stddh_sha1kdf_scheme, prefix + "keyagreementspi$dhwithsha1kdf");
            provider.addalgorithm("keyagreement." + x9objectidentifiers.mqvsinglepass_sha1kdf_scheme, prefix + "keyagreementspi$mqvwithsha1kdf");

            registeroid(provider, x9objectidentifiers.id_ecpublickey, "ec", new keyfactoryspi.ec());
            // todo should this be an alias for ecdh?
            registeroid(provider, x9objectidentifiers.dhsinglepass_stddh_sha1kdf_scheme, "ec", new keyfactoryspi.ec());
            registeroid(provider, x9objectidentifiers.mqvsinglepass_sha1kdf_scheme, "ecmqv", new keyfactoryspi.ecmqv());

            registeroidalgorithmparameters(provider, x9objectidentifiers.id_ecpublickey, "ec");
            // todo should this be an alias for ecdh?
            registeroidalgorithmparameters(provider, x9objectidentifiers.dhsinglepass_stddh_sha1kdf_scheme, "ec");
            registeroidalgorithmparameters(provider, x9objectidentifiers.mqvsinglepass_sha1kdf_scheme, "ec");

            provider.addalgorithm("keyfactory.ec", prefix + "keyfactoryspi$ec");
            provider.addalgorithm("keyfactory.ecdsa", prefix + "keyfactoryspi$ecdsa");
            provider.addalgorithm("keyfactory.ecdh", prefix + "keyfactoryspi$ecdh");
            provider.addalgorithm("keyfactory.ecdhc", prefix + "keyfactoryspi$ecdhc");
            provider.addalgorithm("keyfactory.ecmqv", prefix + "keyfactoryspi$ecmqv");

            provider.addalgorithm("keypairgenerator.ec", prefix + "keypairgeneratorspi$ec");
            provider.addalgorithm("keypairgenerator.ecdsa", prefix + "keypairgeneratorspi$ecdsa");
            provider.addalgorithm("keypairgenerator.ecdh", prefix + "keypairgeneratorspi$ecdh");
            provider.addalgorithm("keypairgenerator.ecdhc", prefix + "keypairgeneratorspi$ecdhc");
            provider.addalgorithm("keypairgenerator.ecies", prefix + "keypairgeneratorspi$ecdh");
            provider.addalgorithm("keypairgenerator.ecmqv", prefix + "keypairgeneratorspi$ecmqv");
            
            provider.addalgorithm("cipher.ecies", prefix + "iescipher$ecies");
            provider.addalgorithm("cipher.ecieswithaes", prefix + "iescipher$ecieswithaes");
            provider.addalgorithm("cipher.ecieswithaes", prefix + "iescipher$ecieswithaes");
            provider.addalgorithm("cipher.ecieswithdesede", prefix + "iescipher$ecieswithdesede");
            provider.addalgorithm("cipher.ecieswithdesede", prefix + "iescipher$ecieswithdesede");

            provider.addalgorithm("signature.ecdsa", prefix + "signaturespi$ecdsa");
            provider.addalgorithm("signature.nonewithecdsa", prefix + "signaturespi$ecdsanone");

            provider.addalgorithm("alg.alias.signature.sha1withecdsa", "ecdsa");
            provider.addalgorithm("alg.alias.signature.ecdsawithsha1", "ecdsa");
            provider.addalgorithm("alg.alias.signature.sha1withecdsa", "ecdsa");
            provider.addalgorithm("alg.alias.signature.ecdsawithsha1", "ecdsa");
            provider.addalgorithm("alg.alias.signature.sha1withecdsa", "ecdsa");
            provider.addalgorithm("alg.alias.signature.ecdsawithsha1", "ecdsa");
            provider.addalgorithm("alg.alias.signature.1.2.840.10045.4.1", "ecdsa");
            provider.addalgorithm("alg.alias.signature." + teletrustobjectidentifiers.ecsignwithsha1, "ecdsa");

            addsignaturealgorithm(provider, "sha224", "ecdsa", prefix + "signaturespi$ecdsa224", x9objectidentifiers.ecdsa_with_sha224);
            addsignaturealgorithm(provider, "sha256", "ecdsa", prefix + "signaturespi$ecdsa256", x9objectidentifiers.ecdsa_with_sha256);
            addsignaturealgorithm(provider, "sha384", "ecdsa", prefix + "signaturespi$ecdsa384", x9objectidentifiers.ecdsa_with_sha384);
            addsignaturealgorithm(provider, "sha512", "ecdsa", prefix + "signaturespi$ecdsa512", x9objectidentifiers.ecdsa_with_sha512);
            addsignaturealgorithm(provider, "ripemd160", "ecdsa", prefix + "signaturespi$ecdsaripemd160",teletrustobjectidentifiers.ecsignwithripemd160);

            provider.addalgorithm("signature.sha1withecnr", prefix + "signaturespi$ecnr");
            provider.addalgorithm("signature.sha224withecnr", prefix + "signaturespi$ecnr224");
            provider.addalgorithm("signature.sha256withecnr", prefix + "signaturespi$ecnr256");
            provider.addalgorithm("signature.sha384withecnr", prefix + "signaturespi$ecnr384");
            provider.addalgorithm("signature.sha512withecnr", prefix + "signaturespi$ecnr512");

            addsignaturealgorithm(provider, "sha1", "cvc-ecdsa", prefix + "signaturespi$eccvcdsa", eacobjectidentifiers.id_ta_ecdsa_sha_1);
            addsignaturealgorithm(provider, "sha224", "cvc-ecdsa", prefix + "signaturespi$eccvcdsa224", eacobjectidentifiers.id_ta_ecdsa_sha_224);
            addsignaturealgorithm(provider, "sha256", "cvc-ecdsa", prefix + "signaturespi$eccvcdsa256", eacobjectidentifiers.id_ta_ecdsa_sha_256);
            addsignaturealgorithm(provider, "sha384", "cvc-ecdsa", prefix + "signaturespi$eccvcdsa384", eacobjectidentifiers.id_ta_ecdsa_sha_384);
            addsignaturealgorithm(provider, "sha512", "cvc-ecdsa", prefix + "signaturespi$eccvcdsa512", eacobjectidentifiers.id_ta_ecdsa_sha_512);
        }
    }
}
