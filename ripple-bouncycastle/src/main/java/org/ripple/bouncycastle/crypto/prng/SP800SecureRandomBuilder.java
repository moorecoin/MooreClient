package org.ripple.bouncycastle.crypto.prng;

import java.security.securerandom;

import org.ripple.bouncycastle.crypto.blockcipher;
import org.ripple.bouncycastle.crypto.digest;
import org.ripple.bouncycastle.crypto.mac;
import org.ripple.bouncycastle.crypto.prng.drbg.ctrsp800drbg;
import org.ripple.bouncycastle.crypto.prng.drbg.dualecsp800drbg;
import org.ripple.bouncycastle.crypto.prng.drbg.hmacsp800drbg;
import org.ripple.bouncycastle.crypto.prng.drbg.hashsp800drbg;
import org.ripple.bouncycastle.crypto.prng.drbg.sp80090drbg;

/**
 * builder class for making securerandom objects based on sp 800-90a deterministic random bit generators (drbg).
 */
public class sp800securerandombuilder
{
    private final securerandom random;
    private final entropysourceprovider entropysourceprovider;

    private byte[] personalizationstring;
    private int securitystrength = 256;
    private int entropybitsrequired = 256;

    /**
     * basic constructor, creates a builder using an entropysourceprovider based on the default securerandom with
     * predictionresistant set to false.
     * <p>
     * any securerandom created from a builder constructed like this will make use of input passed to securerandom.setseed() if
     * the default securerandom does for its generateseed() call.
     * </p>
     */
    public sp800securerandombuilder()
    {
        this(new securerandom(), false);
    }

    /**
     * construct a builder with an entropysourceprovider based on the passed in securerandom and the passed in value
     * for prediction resistance.
     * <p>
     * any securerandom created from a builder constructed like this will make use of input passed to securerandom.setseed() if
     * the passed in securerandom does for its generateseed() call.
     * </p>
     * @param entropysource
     * @param predictionresistant
     */
    public sp800securerandombuilder(securerandom entropysource, boolean predictionresistant)
    {
        this.random = entropysource;
        this.entropysourceprovider = new basicentropysourceprovider(random, predictionresistant);
    }

    /**
     * create a builder which makes creates the securerandom objects from a specified entropy source provider.
     * <p>
     * <b>note:</b> if this constructor is used any calls to setseed() in the resulting securerandom will be ignored.
     * </p>
     * @param entropysourceprovider a provider of entropysource objects.
     */
    public sp800securerandombuilder(entropysourceprovider entropysourceprovider)
    {
        this.random = null;
        this.entropysourceprovider = entropysourceprovider;
    }

    /**
     * set the personalization string for drbg securerandoms created by this builder
     * @param personalizationstring  the personalisation string for the underlying drbg.
     * @return the current builder.
     */
    public sp800securerandombuilder setpersonalizationstring(byte[] personalizationstring)
    {
        this.personalizationstring = personalizationstring;

        return this;
    }

    /**
     * set the security strength required for drbgs used in building securerandom objects.
     *
     * @param securitystrength the security strength (in bits)
     * @return the current builder.
     */
    public sp800securerandombuilder setsecuritystrength(int securitystrength)
    {
        this.securitystrength = securitystrength;

        return this;
    }

    /**
     * set the amount of entropy bits required for seeding and reseeding drbgs used in building securerandom objects.
     *
     * @param entropybitsrequired the number of bits of entropy to be requested from the entropy source on each seed/reseed.
     * @return the current builder.
     */
    public sp800securerandombuilder setentropybitsrequired(int entropybitsrequired)
    {
        this.entropybitsrequired = entropybitsrequired;

        return this;
    }

    /**
     * build a securerandom based on a sp 800-90a hash drbg.
     *
     * @param digest digest algorithm to use in the drbg underneath the securerandom.
     * @param nonce  nonce value to use in drbg construction.
     * @param predictionresistant specify whether the underlying drbg in the resulting securerandom should reseed on each request for bytes.
     * @return a securerandom supported by a hash drbg.
     */
    public sp800securerandom buildhash(digest digest, byte[] nonce, boolean predictionresistant)
    {
        return new sp800securerandom(random, entropysourceprovider.get(entropybitsrequired), new hashdrbgprovider(digest, nonce, personalizationstring, securitystrength), predictionresistant);
    }

    /**
     * build a securerandom based on a sp 800-90a ctr drbg.
     *
     * @param cipher the block cipher to base the drbg on.
     * @param keysizeinbits key size in bits to be used with the block cipher.
     * @param nonce nonce value to use in drbg construction.
     * @param predictionresistant  specify whether the underlying drbg in the resulting securerandom should reseed on each request for bytes.
     * @return  a securerandom supported by a ctr drbg.
     */
    public sp800securerandom buildctr(blockcipher cipher, int keysizeinbits, byte[] nonce, boolean predictionresistant)
    {
        return new sp800securerandom(random, entropysourceprovider.get(entropybitsrequired), new ctrdrbgprovider(cipher, keysizeinbits, nonce, personalizationstring, securitystrength), predictionresistant);
    }

    /**
     * build a securerandom based on a sp 800-90a hmac drbg.
     *
     * @param hmac hmac algorithm to use in the drbg underneath the securerandom.
     * @param nonce  nonce value to use in drbg construction.
     * @param predictionresistant specify whether the underlying drbg in the resulting securerandom should reseed on each request for bytes.
     * @return a securerandom supported by a hmac drbg.
     */
    public sp800securerandom buildhmac(mac hmac, byte[] nonce, boolean predictionresistant)
    {
        return new sp800securerandom(random, entropysourceprovider.get(entropybitsrequired), new hmacdrbgprovider(hmac, nonce, personalizationstring, securitystrength), predictionresistant);
    }

    /**
     * build a securerandom based on a sp 800-90a dual ec drbg.
     *
     * @param digest digest algorithm to use in the drbg underneath the securerandom.
     * @param nonce  nonce value to use in drbg construction.
     * @param predictionresistant specify whether the underlying drbg in the resulting securerandom should reseed on each request for bytes.
     * @return a securerandom supported by a dual ec drbg.
     */
    public sp800securerandom builddualec(digest digest, byte[] nonce, boolean predictionresistant)
    {
        return new sp800securerandom(random, entropysourceprovider.get(entropybitsrequired), new dualecdrbgprovider(digest, nonce, personalizationstring, securitystrength), predictionresistant);
    }

    private static class hashdrbgprovider
        implements drbgprovider
    {
        private final digest digest;
        private final byte[] nonce;
        private final byte[] personalizationstring;
        private final int securitystrength;

        public hashdrbgprovider(digest digest, byte[] nonce, byte[] personalizationstring, int securitystrength)
        {
            this.digest = digest;
            this.nonce = nonce;
            this.personalizationstring = personalizationstring;
            this.securitystrength = securitystrength;
        }

        public sp80090drbg get(entropysource entropysource)
        {
            return new hashsp800drbg(digest, securitystrength, entropysource, personalizationstring, nonce);
        }
    }

    private static class dualecdrbgprovider
        implements drbgprovider
    {
        private final digest digest;
        private final byte[] nonce;
        private final byte[] personalizationstring;
        private final int securitystrength;

        public dualecdrbgprovider(digest digest, byte[] nonce, byte[] personalizationstring, int securitystrength)
        {
            this.digest = digest;
            this.nonce = nonce;
            this.personalizationstring = personalizationstring;
            this.securitystrength = securitystrength;
        }

        public sp80090drbg get(entropysource entropysource)
        {
            return new dualecsp800drbg(digest, securitystrength, entropysource, personalizationstring, nonce);
        }
    }

    private static class hmacdrbgprovider
        implements drbgprovider
    {
        private final mac hmac;
        private final byte[] nonce;
        private final byte[] personalizationstring;
        private final int securitystrength;

        public hmacdrbgprovider(mac hmac, byte[] nonce, byte[] personalizationstring, int securitystrength)
        {
            this.hmac = hmac;
            this.nonce = nonce;
            this.personalizationstring = personalizationstring;
            this.securitystrength = securitystrength;
        }

        public sp80090drbg get(entropysource entropysource)
        {
            return new hmacsp800drbg(hmac, securitystrength, entropysource, personalizationstring, nonce);
        }
    }

    private static class ctrdrbgprovider
        implements drbgprovider
    {

        private final blockcipher blockcipher;
        private final int keysizeinbits;
        private final byte[] nonce;
        private final byte[] personalizationstring;
        private final int securitystrength;

        public ctrdrbgprovider(blockcipher blockcipher, int keysizeinbits, byte[] nonce, byte[] personalizationstring, int securitystrength)
        {
            this.blockcipher = blockcipher;
            this.keysizeinbits = keysizeinbits;
            this.nonce = nonce;
            this.personalizationstring = personalizationstring;
            this.securitystrength = securitystrength;
        }

        public sp80090drbg get(entropysource entropysource)
        {
            return new ctrsp800drbg(blockcipher, keysizeinbits, securitystrength, entropysource, personalizationstring, nonce);
        }
    }
}
