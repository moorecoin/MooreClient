package org.ripple.bouncycastle.jcajce.provider.asymmetric;

import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.oiw.oiwobjectidentifiers;
import org.ripple.bouncycastle.asn1.pkcs.pkcsobjectidentifiers;
import org.ripple.bouncycastle.asn1.teletrust.teletrustobjectidentifiers;
import org.ripple.bouncycastle.asn1.x509.x509objectidentifiers;
import org.ripple.bouncycastle.jcajce.provider.asymmetric.rsa.keyfactoryspi;
import org.ripple.bouncycastle.jcajce.provider.config.configurableprovider;
import org.ripple.bouncycastle.jcajce.provider.util.asymmetricalgorithmprovider;
import org.ripple.bouncycastle.jcajce.provider.util.asymmetrickeyinfoconverter;

public class rsa
{
    private static final string prefix = "org.bouncycastle.jcajce.provider.asymmetric" + ".rsa.";

    public static class mappings
        extends asymmetricalgorithmprovider
    {
        public mappings()
        {
        }

        public void configure(configurableprovider provider)
        {
            provider.addalgorithm("algorithmparameters.oaep", prefix + "algorithmparametersspi$oaep");
            provider.addalgorithm("algorithmparameters.pss", prefix + "algorithmparametersspi$pss");

            provider.addalgorithm("alg.alias.algorithmparameters.rsapss", "pss");
            provider.addalgorithm("alg.alias.algorithmparameters.rsassa-pss", "pss");

            provider.addalgorithm("alg.alias.algorithmparameters.sha224withrsa/pss", "pss");
            provider.addalgorithm("alg.alias.algorithmparameters.sha256withrsa/pss", "pss");
            provider.addalgorithm("alg.alias.algorithmparameters.sha384withrsa/pss", "pss");
            provider.addalgorithm("alg.alias.algorithmparameters.sha512withrsa/pss", "pss");

            provider.addalgorithm("alg.alias.algorithmparameters.sha224withrsaandmgf1", "pss");
            provider.addalgorithm("alg.alias.algorithmparameters.sha256withrsaandmgf1", "pss");
            provider.addalgorithm("alg.alias.algorithmparameters.sha384withrsaandmgf1", "pss");
            provider.addalgorithm("alg.alias.algorithmparameters.sha512withrsaandmgf1", "pss");
            provider.addalgorithm("alg.alias.algorithmparameters.rawrsapss", "pss");
            provider.addalgorithm("alg.alias.algorithmparameters.nonewithrsapss", "pss");
            provider.addalgorithm("alg.alias.algorithmparameters.nonewithrsassa-pss", "pss");
            provider.addalgorithm("alg.alias.algorithmparameters.nonewithrsaandmgf1", "pss");

            provider.addalgorithm("cipher.rsa", prefix + "cipherspi$nopadding");
            provider.addalgorithm("cipher.rsa/raw", prefix + "cipherspi$nopadding");
            provider.addalgorithm("cipher.rsa/pkcs1", prefix + "cipherspi$pkcs1v1_5padding");
            provider.addalgorithm("cipher.1.2.840.113549.1.1.1", prefix + "cipherspi$pkcs1v1_5padding");
            provider.addalgorithm("cipher.2.5.8.1.1", prefix + "cipherspi$pkcs1v1_5padding");
            provider.addalgorithm("cipher.rsa/1", prefix + "cipherspi$pkcs1v1_5padding_privateonly");
            provider.addalgorithm("cipher.rsa/2", prefix + "cipherspi$pkcs1v1_5padding_publiconly");
            provider.addalgorithm("cipher.rsa/oaep", prefix + "cipherspi$oaeppadding");
            provider.addalgorithm("cipher." + pkcsobjectidentifiers.id_rsaes_oaep, prefix + "cipherspi$oaeppadding");
            provider.addalgorithm("cipher.rsa/iso9796-1", prefix + "cipherspi$iso9796d1padding");

            provider.addalgorithm("alg.alias.cipher.rsa//raw", "rsa");
            provider.addalgorithm("alg.alias.cipher.rsa//nopadding", "rsa");
            provider.addalgorithm("alg.alias.cipher.rsa//pkcs1padding", "rsa/pkcs1");
            provider.addalgorithm("alg.alias.cipher.rsa//oaeppadding", "rsa/oaep");
            provider.addalgorithm("alg.alias.cipher.rsa//iso9796-1padding", "rsa/iso9796-1");

            provider.addalgorithm("keyfactory.rsa", prefix + "keyfactoryspi");
            provider.addalgorithm("keypairgenerator.rsa", prefix + "keypairgeneratorspi");

            asymmetrickeyinfoconverter keyfact = new keyfactoryspi();

            registeroid(provider, pkcsobjectidentifiers.rsaencryption, "rsa", keyfact);
            registeroid(provider, x509objectidentifiers.id_ea_rsa, "rsa", keyfact);
            registeroid(provider, pkcsobjectidentifiers.id_rsaes_oaep, "rsa", keyfact);
            registeroid(provider, pkcsobjectidentifiers.id_rsassa_pss, "rsa", keyfact);

            registeroidalgorithmparameters(provider, pkcsobjectidentifiers.rsaencryption, "rsa");
            registeroidalgorithmparameters(provider, x509objectidentifiers.id_ea_rsa, "rsa");
            registeroidalgorithmparameters(provider, pkcsobjectidentifiers.id_rsaes_oaep, "oaep");
            registeroidalgorithmparameters(provider, pkcsobjectidentifiers.id_rsassa_pss, "pss");


            provider.addalgorithm("signature.rsassa-pss", prefix + "psssignaturespi$psswithrsa");
            provider.addalgorithm("signature." + pkcsobjectidentifiers.id_rsassa_pss, prefix + "psssignaturespi$psswithrsa");
            provider.addalgorithm("signature.oid." + pkcsobjectidentifiers.id_rsassa_pss, prefix + "psssignaturespi$psswithrsa");

            provider.addalgorithm("signature.sha224withrsa/pss", prefix + "psssignaturespi$sha224withrsa");
            provider.addalgorithm("signature.sha256withrsa/pss", prefix + "psssignaturespi$sha256withrsa");
            provider.addalgorithm("signature.sha384withrsa/pss", prefix + "psssignaturespi$sha384withrsa");
            provider.addalgorithm("signature.sha512withrsa/pss", prefix + "psssignaturespi$sha512withrsa");

            provider.addalgorithm("signature.rsa", prefix + "digestsignaturespi$nonersa");
            provider.addalgorithm("signature.rawrsassa-pss", prefix + "psssignaturespi$nonepss");

            provider.addalgorithm("alg.alias.signature.rawrsa", "rsa");
            provider.addalgorithm("alg.alias.signature.nonewithrsa", "rsa");
            provider.addalgorithm("alg.alias.signature.rawrsapss", "rawrsassa-pss");
            provider.addalgorithm("alg.alias.signature.nonewithrsapss", "rawrsassa-pss");
            provider.addalgorithm("alg.alias.signature.nonewithrsassa-pss", "rawrsassa-pss");
            provider.addalgorithm("alg.alias.signature.nonewithrsaandmgf1", "rawrsassa-pss");
            provider.addalgorithm("alg.alias.signature.rsapss", "rsassa-pss");


            provider.addalgorithm("alg.alias.signature.sha224withrsaandmgf1", "sha224withrsa/pss");
            provider.addalgorithm("alg.alias.signature.sha256withrsaandmgf1", "sha256withrsa/pss");
            provider.addalgorithm("alg.alias.signature.sha384withrsaandmgf1", "sha384withrsa/pss");
            provider.addalgorithm("alg.alias.signature.sha512withrsaandmgf1", "sha512withrsa/pss");
            provider.addalgorithm("alg.alias.signature.sha224withrsaandmgf1", "sha224withrsa/pss");
            provider.addalgorithm("alg.alias.signature.sha256withrsaandmgf1", "sha256withrsa/pss");
            provider.addalgorithm("alg.alias.signature.sha384withrsaandmgf1", "sha384withrsa/pss");
            provider.addalgorithm("alg.alias.signature.sha512withrsaandmgf1", "sha512withrsa/pss");

            if (provider.hasalgorithm("messagedigest", "md2"))
            {
                adddigestsignature(provider, "md2", prefix + "digestsignaturespi$md2", pkcsobjectidentifiers.md2withrsaencryption);
            }

            if (provider.hasalgorithm("messagedigest", "md4"))
            {
                adddigestsignature(provider, "md4", prefix + "digestsignaturespi$md4", pkcsobjectidentifiers.md4withrsaencryption);
            }

            if (provider.hasalgorithm("messagedigest", "md5"))
            {
                adddigestsignature(provider, "md5", prefix + "digestsignaturespi$md5", pkcsobjectidentifiers.md5withrsaencryption);
                provider.addalgorithm("signature.md5withrsa/iso9796-2", prefix + "isosignaturespi$md5withrsaencryption");
                provider.addalgorithm("alg.alias.signature.md5withrsa/iso9796-2", "md5withrsa/iso9796-2");
            }

            if (provider.hasalgorithm("messagedigest", "sha1"))
            {
                provider.addalgorithm("alg.alias.algorithmparameters.sha1withrsa/pss", "pss");
                provider.addalgorithm("alg.alias.algorithmparameters.sha1withrsaandmgf1", "pss");
                provider.addalgorithm("signature.sha1withrsa/pss", prefix + "psssignaturespi$sha1withrsa");
                provider.addalgorithm("alg.alias.signature.sha1withrsaandmgf1", "sha1withrsa/pss");
                provider.addalgorithm("alg.alias.signature.sha1withrsaandmgf1", "sha1withrsa/pss");

                adddigestsignature(provider, "sha1", prefix + "digestsignaturespi$sha1", pkcsobjectidentifiers.sha1withrsaencryption);

                provider.addalgorithm("alg.alias.signature.sha1withrsa/iso9796-2", "sha1withrsa/iso9796-2");
                provider.addalgorithm("signature.sha1withrsa/iso9796-2", prefix + "isosignaturespi$sha1withrsaencryption");
                provider.addalgorithm("alg.alias.signature." + oiwobjectidentifiers.sha1withrsa, "sha1withrsa");
                provider.addalgorithm("alg.alias.signature.oid." + oiwobjectidentifiers.sha1withrsa, "sha1withrsa");
            }

            adddigestsignature(provider, "sha224", prefix + "digestsignaturespi$sha224", pkcsobjectidentifiers.sha224withrsaencryption);
            adddigestsignature(provider, "sha256", prefix + "digestsignaturespi$sha256", pkcsobjectidentifiers.sha256withrsaencryption);
            adddigestsignature(provider, "sha384", prefix + "digestsignaturespi$sha384", pkcsobjectidentifiers.sha384withrsaencryption);
            adddigestsignature(provider, "sha512", prefix + "digestsignaturespi$sha512", pkcsobjectidentifiers.sha512withrsaencryption);

            if (provider.hasalgorithm("messagedigest", "ripemd128"))
            {
                adddigestsignature(provider, "ripemd128", prefix + "digestsignaturespi$ripemd128", teletrustobjectidentifiers.rsasignaturewithripemd128);
                adddigestsignature(provider, "rmd128", prefix + "digestsignaturespi$ripemd128", null);
            }

            if (provider.hasalgorithm("messagedigest", "ripemd160"))
            {
                adddigestsignature(provider, "ripemd160", prefix + "digestsignaturespi$ripemd160", teletrustobjectidentifiers.rsasignaturewithripemd160);
                adddigestsignature(provider, "rmd160", prefix + "digestsignaturespi$ripemd160", null);
                provider.addalgorithm("alg.alias.signature.ripemd160withrsa/iso9796-2", "ripemd160withrsa/iso9796-2");
                provider.addalgorithm("signature.ripemd160withrsa/iso9796-2", prefix + "isosignaturespi$ripemd160withrsaencryption");
            }

            if (provider.hasalgorithm("messagedigest", "ripemd256"))
            {
                adddigestsignature(provider, "ripemd256", prefix + "digestsignaturespi$ripemd256", teletrustobjectidentifiers.rsasignaturewithripemd256);
                adddigestsignature(provider, "rmd256", prefix + "digestsignaturespi$ripemd256", null);
            }
        }

        private void adddigestsignature(
            configurableprovider provider,
            string digest,
            string classname,
            asn1objectidentifier oid)
        {
            string mainname = digest + "withrsa";
            string jdk11variation1 = digest + "withrsa";
            string jdk11variation2 = digest + "withrsa";
            string alias = digest + "/" + "rsa";
            string longname = digest + "withrsaencryption";
            string longjdk11variation1 = digest + "withrsaencryption";
            string longjdk11variation2 = digest + "withrsaencryption";

            provider.addalgorithm("signature." + mainname, classname);
            provider.addalgorithm("alg.alias.signature." + jdk11variation1, mainname);
            provider.addalgorithm("alg.alias.signature." + jdk11variation2, mainname);
            provider.addalgorithm("alg.alias.signature." + longname, mainname);
            provider.addalgorithm("alg.alias.signature." + longjdk11variation1, mainname);
            provider.addalgorithm("alg.alias.signature." + longjdk11variation2, mainname);
            provider.addalgorithm("alg.alias.signature." + alias, mainname);

            if (oid != null)
            {
                provider.addalgorithm("alg.alias.signature." + oid, mainname);
                provider.addalgorithm("alg.alias.signature.oid." + oid, mainname);
            }
        }
    }
}
