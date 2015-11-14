package org.ripple.bouncycastle.crypto.generators;

import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.digest;
import org.ripple.bouncycastle.crypto.pbeparametersgenerator;
import org.ripple.bouncycastle.crypto.params.keyparameter;
import org.ripple.bouncycastle.crypto.params.parameterswithiv;

/**
 * generator for pbe derived keys and ivs as defined by pkcs 5 v2.0 scheme 1.
 * note this generator is limited to the size of the hash produced by the
 * digest used to drive it.
 * <p>
 * the document this implementation is based on can be found at
 * <a href=http://www.rsasecurity.com/rsalabs/pkcs/pkcs-5/index.html>
 * rsa's pkcs5 page</a>
 */
public class pkcs5s1parametersgenerator
    extends pbeparametersgenerator
{
    private digest  digest;

    /**
     * construct a pkcs 5 scheme 1 parameters generator. 
     *
     * @param digest the digest to be used as the source of derived keys.
     */
    public pkcs5s1parametersgenerator(
        digest  digest)
    {
        this.digest = digest;
    }

    /**
     * the derived key function, the ith hash of the password and the salt.
     */
    private byte[] generatederivedkey()
    {
        byte[] digestbytes = new byte[digest.getdigestsize()];

        digest.update(password, 0, password.length);
        digest.update(salt, 0, salt.length);

        digest.dofinal(digestbytes, 0);
        for (int i = 1; i < iterationcount; i++)
        {
            digest.update(digestbytes, 0, digestbytes.length);
            digest.dofinal(digestbytes, 0);
        }

        return digestbytes;
    }

    /**
     * generate a key parameter derived from the password, salt, and iteration
     * count we are currently initialised with.
     *
     * @param keysize the size of the key we want (in bits)
     * @return a keyparameter object.
     * @exception illegalargumentexception if the key length larger than the base hash size.
     */
    public cipherparameters generatederivedparameters(
        int keysize)
    {
        keysize = keysize / 8;

        if (keysize > digest.getdigestsize())
        {
            throw new illegalargumentexception(
                   "can't generate a derived key " + keysize + " bytes long.");
        }

        byte[]  dkey = generatederivedkey();

        return new keyparameter(dkey, 0, keysize);
    }

    /**
     * generate a key with initialisation vector parameter derived from
     * the password, salt, and iteration count we are currently initialised
     * with.
     *
     * @param keysize the size of the key we want (in bits)
     * @param ivsize the size of the iv we want (in bits)
     * @return a parameterswithiv object.
     * @exception illegalargumentexception if keysize + ivsize is larger than the base hash size.
     */
    public cipherparameters generatederivedparameters(
        int     keysize,
        int     ivsize)
    {
        keysize = keysize / 8;
        ivsize = ivsize / 8;

        if ((keysize + ivsize) > digest.getdigestsize())
        {
            throw new illegalargumentexception(
                   "can't generate a derived key " + (keysize + ivsize) + " bytes long.");
        }

        byte[]  dkey = generatederivedkey();

        return new parameterswithiv(new keyparameter(dkey, 0, keysize), dkey, keysize, ivsize);
    }

    /**
     * generate a key parameter for use with a mac derived from the password,
     * salt, and iteration count we are currently initialised with.
     *
     * @param keysize the size of the key we want (in bits)
     * @return a keyparameter object.
     * @exception illegalargumentexception if the key length larger than the base hash size.
     */
    public cipherparameters generatederivedmacparameters(
        int keysize)
    {
        return generatederivedparameters(keysize);
    }
}
