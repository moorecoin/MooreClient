package org.ripple.bouncycastle.crypto.tls;

import java.io.ioexception;

import org.ripple.bouncycastle.crypto.blockcipher;
import org.ripple.bouncycastle.crypto.digest;
import org.ripple.bouncycastle.crypto.streamcipher;
import org.ripple.bouncycastle.crypto.digests.md5digest;
import org.ripple.bouncycastle.crypto.digests.sha1digest;
import org.ripple.bouncycastle.crypto.digests.sha256digest;
import org.ripple.bouncycastle.crypto.digests.sha384digest;
import org.ripple.bouncycastle.crypto.digests.sha512digest;
import org.ripple.bouncycastle.crypto.engines.aesfastengine;
import org.ripple.bouncycastle.crypto.engines.camelliaengine;
import org.ripple.bouncycastle.crypto.engines.desedeengine;
import org.ripple.bouncycastle.crypto.engines.rc4engine;
import org.ripple.bouncycastle.crypto.engines.seedengine;
import org.ripple.bouncycastle.crypto.modes.aeadblockcipher;
import org.ripple.bouncycastle.crypto.modes.cbcblockcipher;
import org.ripple.bouncycastle.crypto.modes.gcmblockcipher;

public class defaulttlscipherfactory
    extends abstracttlscipherfactory
{

    public tlscipher createcipher(tlscontext context, int encryptionalgorithm, int macalgorithm)
        throws ioexception
    {

        switch (encryptionalgorithm)
        {
        case encryptionalgorithm._3des_ede_cbc:
            return createdesedecipher(context, macalgorithm);
        case encryptionalgorithm.aes_128_cbc:
            return createaescipher(context, 16, macalgorithm);
        case encryptionalgorithm.aes_128_gcm:
            // note: ignores macalgorithm
            return createcipher_aes_gcm(context, 16, 16);
        case encryptionalgorithm.aes_256_cbc:
            return createaescipher(context, 32, macalgorithm);
        case encryptionalgorithm.aes_256_gcm:
            // note: ignores macalgorithm
            return createcipher_aes_gcm(context, 32, 16);
        case encryptionalgorithm.camellia_128_cbc:
            return createcamelliacipher(context, 16, macalgorithm);
        case encryptionalgorithm.camellia_256_cbc:
            return createcamelliacipher(context, 32, macalgorithm);
        case encryptionalgorithm.null:
            return createnullcipher(context, macalgorithm);
        case encryptionalgorithm.rc4_128:
            return createrc4cipher(context, 16, macalgorithm);
        case encryptionalgorithm.seed_cbc:
            return createseedcipher(context, macalgorithm);
        default:
            throw new tlsfatalalert(alertdescription.internal_error);
        }
    }

    protected tlsblockcipher createaescipher(tlscontext context, int cipherkeysize, int macalgorithm)
        throws ioexception
    {
        return new tlsblockcipher(context, createaesblockcipher(), createaesblockcipher(),
            createhmacdigest(macalgorithm), createhmacdigest(macalgorithm), cipherkeysize);
    }

    protected tlsaeadcipher createcipher_aes_gcm(tlscontext context, int cipherkeysize, int macsize)
        throws ioexception
    {
        return new tlsaeadcipher(context, createaeadblockcipher_aes_gcm(),
            createaeadblockcipher_aes_gcm(), cipherkeysize, macsize);
    }

    protected tlsblockcipher createcamelliacipher(tlscontext context, int cipherkeysize,
                                                  int macalgorithm)
        throws ioexception
    {
        return new tlsblockcipher(context, createcamelliablockcipher(),
            createcamelliablockcipher(), createhmacdigest(macalgorithm),
            createhmacdigest(macalgorithm), cipherkeysize);
    }

    protected tlsnullcipher createnullcipher(tlscontext context, int macalgorithm)
        throws ioexception
    {
        return new tlsnullcipher(context, createhmacdigest(macalgorithm),
            createhmacdigest(macalgorithm));
    }

    protected tlsstreamcipher createrc4cipher(tlscontext context, int cipherkeysize,
                                              int macalgorithm)
        throws ioexception
    {
        return new tlsstreamcipher(context, createrc4streamcipher(), createrc4streamcipher(),
            createhmacdigest(macalgorithm), createhmacdigest(macalgorithm), cipherkeysize);
    }

    protected tlsblockcipher createdesedecipher(tlscontext context, int macalgorithm)
        throws ioexception
    {
        return new tlsblockcipher(context, createdesedeblockcipher(), createdesedeblockcipher(),
            createhmacdigest(macalgorithm), createhmacdigest(macalgorithm), 24);
    }

    protected tlsblockcipher createseedcipher(tlscontext context, int macalgorithm)
        throws ioexception
    {
        return new tlsblockcipher(context, createseedblockcipher(), createseedblockcipher(),
            createhmacdigest(macalgorithm), createhmacdigest(macalgorithm), 16);
    }

    protected streamcipher createrc4streamcipher()
    {
        return new rc4engine();
    }

    protected blockcipher createaesblockcipher()
    {
        return new cbcblockcipher(new aesfastengine());
    }

    protected aeadblockcipher createaeadblockcipher_aes_gcm()
    {
        // todo consider allowing custom configuration of multiplier
        return new gcmblockcipher(new aesfastengine());
    }

    protected blockcipher createcamelliablockcipher()
    {
        return new cbcblockcipher(new camelliaengine());
    }

    protected blockcipher createdesedeblockcipher()
    {
        return new cbcblockcipher(new desedeengine());
    }

    protected blockcipher createseedblockcipher()
    {
        return new cbcblockcipher(new seedengine());
    }

    protected digest createhmacdigest(int macalgorithm)
        throws ioexception
    {
        switch (macalgorithm)
        {
        case macalgorithm._null:
            return null;
        case macalgorithm.hmac_md5:
            return new md5digest();
        case macalgorithm.hmac_sha1:
            return new sha1digest();
        case macalgorithm.hmac_sha256:
            return new sha256digest();
        case macalgorithm.hmac_sha384:
            return new sha384digest();
        case macalgorithm.hmac_sha512:
            return new sha512digest();
        default:
            throw new tlsfatalalert(alertdescription.internal_error);
        }
    }
}
