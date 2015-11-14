package org.ripple.bouncycastle.openpgp.operator.jcajce;

import javax.crypto.secretkey;
import javax.crypto.spec.secretkeyspec;

import org.ripple.bouncycastle.bcpg.hashalgorithmtags;
import org.ripple.bouncycastle.bcpg.publickeyalgorithmtags;
import org.ripple.bouncycastle.bcpg.symmetrickeyalgorithmtags;
import org.ripple.bouncycastle.openpgp.pgpexception;

/**
 * basic utility class
 */
class pgputil
{
    static string getdigestname(
        int        hashalgorithm)
        throws pgpexception
    {
        switch (hashalgorithm)
        {
        case hashalgorithmtags.sha1:
            return "sha1";
        case hashalgorithmtags.md2:
            return "md2";
        case hashalgorithmtags.md5:
            return "md5";
        case hashalgorithmtags.ripemd160:
            return "ripemd160";
        case hashalgorithmtags.sha256:
            return "sha256";
        case hashalgorithmtags.sha384:
            return "sha384";
        case hashalgorithmtags.sha512:
            return "sha512";
        case hashalgorithmtags.sha224:
            return "sha224";
        case hashalgorithmtags.tiger_192:
            return "tiger";
        default:
            throw new pgpexception("unknown hash algorithm tag in getdigestname: " + hashalgorithm);
        }
    }
    
    static string getsignaturename(
        int        keyalgorithm,
        int        hashalgorithm)
        throws pgpexception
    {
        string     encalg;
                
        switch (keyalgorithm)
        {
        case publickeyalgorithmtags.rsa_general:
        case publickeyalgorithmtags.rsa_sign:
            encalg = "rsa";
            break;
        case publickeyalgorithmtags.dsa:
            encalg = "dsa";
            break;
        case publickeyalgorithmtags.elgamal_encrypt: // in some malformed cases.
        case publickeyalgorithmtags.elgamal_general:
            encalg = "elgamal";
            break;
        default:
            throw new pgpexception("unknown algorithm tag in signature:" + keyalgorithm);
        }

        return getdigestname(hashalgorithm) + "with" + encalg;
    }
    
    static string getsymmetricciphername(
        int    algorithm)
    {
        switch (algorithm)
        {
        case symmetrickeyalgorithmtags.null:
            return null;
        case symmetrickeyalgorithmtags.triple_des:
            return "desede";
        case symmetrickeyalgorithmtags.idea:
            return "idea";
        case symmetrickeyalgorithmtags.cast5:
            return "cast5";
        case symmetrickeyalgorithmtags.blowfish:
            return "blowfish";
        case symmetrickeyalgorithmtags.safer:
            return "safer";
        case symmetrickeyalgorithmtags.des:
            return "des";
        case symmetrickeyalgorithmtags.aes_128:
            return "aes";
        case symmetrickeyalgorithmtags.aes_192:
            return "aes";
        case symmetrickeyalgorithmtags.aes_256:
            return "aes";
        case symmetrickeyalgorithmtags.twofish:
            return "twofish";
        default:
            throw new illegalargumentexception("unknown symmetric algorithm: " + algorithm);
        }
    }
    
    public static secretkey makesymmetrickey(
        int             algorithm,
        byte[]          keybytes)
        throws pgpexception
    {
        string    algname;
        
        switch (algorithm)
        {
        case symmetrickeyalgorithmtags.triple_des:
            algname = "des_ede";
            break;
        case symmetrickeyalgorithmtags.idea:
            algname = "idea";
            break;
        case symmetrickeyalgorithmtags.cast5:
            algname = "cast5";
            break;
        case symmetrickeyalgorithmtags.blowfish:
            algname = "blowfish";
            break;
        case symmetrickeyalgorithmtags.safer:
            algname = "safer";
            break;
        case symmetrickeyalgorithmtags.des:
            algname = "des";
            break;
        case symmetrickeyalgorithmtags.aes_128:
            algname = "aes";
            break;
        case symmetrickeyalgorithmtags.aes_192:
            algname = "aes";
            break;
        case symmetrickeyalgorithmtags.aes_256:
            algname = "aes";
            break;
        case symmetrickeyalgorithmtags.twofish:
            algname = "twofish";
            break;
        default:
            throw new pgpexception("unknown symmetric algorithm: " + algorithm);
        }

        return new secretkeyspec(keybytes, algname);
    }
}
