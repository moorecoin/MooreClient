package org.ripple.bouncycastle.openpgp.operator.bc;

import org.ripple.bouncycastle.bcpg.hashalgorithmtags;
import org.ripple.bouncycastle.bcpg.publickeyalgorithmtags;
import org.ripple.bouncycastle.bcpg.symmetrickeyalgorithmtags;
import org.ripple.bouncycastle.crypto.asymmetricblockcipher;
import org.ripple.bouncycastle.crypto.blockcipher;
import org.ripple.bouncycastle.crypto.digest;
import org.ripple.bouncycastle.crypto.signer;
import org.ripple.bouncycastle.crypto.digests.md2digest;
import org.ripple.bouncycastle.crypto.digests.md5digest;
import org.ripple.bouncycastle.crypto.digests.ripemd160digest;
import org.ripple.bouncycastle.crypto.digests.sha1digest;
import org.ripple.bouncycastle.crypto.digests.sha224digest;
import org.ripple.bouncycastle.crypto.digests.sha256digest;
import org.ripple.bouncycastle.crypto.digests.sha384digest;
import org.ripple.bouncycastle.crypto.digests.sha512digest;
import org.ripple.bouncycastle.crypto.digests.tigerdigest;
import org.ripple.bouncycastle.crypto.encodings.pkcs1encoding;
import org.ripple.bouncycastle.crypto.engines.aesengine;
import org.ripple.bouncycastle.crypto.engines.blowfishengine;
import org.ripple.bouncycastle.crypto.engines.cast5engine;
import org.ripple.bouncycastle.crypto.engines.desengine;
import org.ripple.bouncycastle.crypto.engines.desedeengine;
import org.ripple.bouncycastle.crypto.engines.elgamalengine;
import org.ripple.bouncycastle.crypto.engines.rsablindedengine;
import org.ripple.bouncycastle.crypto.engines.twofishengine;
import org.ripple.bouncycastle.crypto.signers.dsadigestsigner;
import org.ripple.bouncycastle.crypto.signers.dsasigner;
import org.ripple.bouncycastle.crypto.signers.rsadigestsigner;
import org.ripple.bouncycastle.openpgp.pgpexception;
import org.ripple.bouncycastle.openpgp.pgppublickey;

class bcimplprovider
{
    static digest createdigest(int algorithm)
        throws pgpexception
    {
        switch (algorithm)
        {
        case hashalgorithmtags.sha1:
            return new sha1digest();
        case hashalgorithmtags.sha224:
            return new sha224digest();
        case hashalgorithmtags.sha256:
            return new sha256digest();
        case hashalgorithmtags.sha384:
            return new sha384digest();
        case hashalgorithmtags.sha512:
            return new sha512digest();
        case hashalgorithmtags.md2:
            return new md2digest();
        case hashalgorithmtags.md5:
            return new md5digest();
        case hashalgorithmtags.ripemd160:
            return new ripemd160digest();
        case hashalgorithmtags.tiger_192:
            return new tigerdigest();
        default:
            throw new pgpexception("cannot recognise digest");
        }
    }

    static signer createsigner(int keyalgorithm, int hashalgorithm)
        throws pgpexception
    {
        switch(keyalgorithm)
        {
        case publickeyalgorithmtags.rsa_general:
        case publickeyalgorithmtags.rsa_sign:
            return new rsadigestsigner(createdigest(hashalgorithm));
        case publickeyalgorithmtags.dsa:
            return new dsadigestsigner(new dsasigner(), createdigest(hashalgorithm));
        default:
            throw new pgpexception("cannot recognise keyalgorithm");
        }
    }

    static blockcipher createblockcipher(int encalgorithm)
        throws pgpexception
    {
        blockcipher engine;

        switch (encalgorithm)
        {
        case symmetrickeyalgorithmtags.aes_128:
        case symmetrickeyalgorithmtags.aes_192:
        case symmetrickeyalgorithmtags.aes_256:
            engine = new aesengine();
            break;
        case symmetrickeyalgorithmtags.blowfish:
            engine = new blowfishengine();
            break;
        case symmetrickeyalgorithmtags.cast5:
            engine = new cast5engine();
            break;
        case symmetrickeyalgorithmtags.des:
            engine = new desengine();
            break;
        case symmetrickeyalgorithmtags.twofish:
            engine = new twofishengine();
            break;
        case symmetrickeyalgorithmtags.triple_des:
            engine = new desedeengine();
            break;
        default:
            throw new pgpexception("cannot recognise cipher");
        }

        return engine;
    }

    static asymmetricblockcipher createpublickeycipher(int encalgorithm)
        throws pgpexception
    {
        asymmetricblockcipher c;

        switch (encalgorithm)
        {
        case pgppublickey.rsa_encrypt:
        case pgppublickey.rsa_general:
            c = new pkcs1encoding(new rsablindedengine());
            break;
        case pgppublickey.elgamal_encrypt:
        case pgppublickey.elgamal_general:
            c = new pkcs1encoding(new elgamalengine());
            break;
        case pgppublickey.dsa:
            throw new pgpexception("can't use dsa for encryption.");
        case pgppublickey.ecdsa:
            throw new pgpexception("can't use ecdsa for encryption.");
        default:
            throw new pgpexception("unknown asymmetric algorithm: " + encalgorithm);
        }

        return c;
    }
}
