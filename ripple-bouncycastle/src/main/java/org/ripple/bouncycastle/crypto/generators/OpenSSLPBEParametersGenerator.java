package org.ripple.bouncycastle.crypto.generators;

import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.digest;
import org.ripple.bouncycastle.crypto.pbeparametersgenerator;
import org.ripple.bouncycastle.crypto.digests.md5digest;
import org.ripple.bouncycastle.crypto.params.keyparameter;
import org.ripple.bouncycastle.crypto.params.parameterswithiv;

/**
 * generator for pbe derived keys and ivs as usd by openssl.
 * <p>
 * the scheme is a simple extension of pkcs 5 v2.0 scheme 1 using md5 with an
 * iteration count of 1.
 * <p>
 */
public class opensslpbeparametersgenerator
    extends pbeparametersgenerator
{
    private digest  digest = new md5digest();

    /**
     * construct a openssl parameters generator. 
     */
    public opensslpbeparametersgenerator()
    {
    }

    /**
     * initialise - note the iteration count for this algorithm is fixed at 1.
     * 
     * @param password password to use.
     * @param salt salt to use.
     */
    public void init(
       byte[] password,
       byte[] salt)
    {
        super.init(password, salt, 1);
    }
    
    /**
     * the derived key function, the ith hash of the password and the salt.
     */
    private byte[] generatederivedkey(
        int bytesneeded)
    {
        byte[]  buf = new byte[digest.getdigestsize()];
        byte[]  key = new byte[bytesneeded];
        int     offset = 0;
        
        for (;;)
        {
            digest.update(password, 0, password.length);
            digest.update(salt, 0, salt.length);

            digest.dofinal(buf, 0);
            
            int len = (bytesneeded > buf.length) ? buf.length : bytesneeded;
            system.arraycopy(buf, 0, key, offset, len);
            offset += len;

            // check if we need any more
            bytesneeded -= len;
            if (bytesneeded == 0)
            {
                break;
            }

            // do another round
            digest.reset();
            digest.update(buf, 0, buf.length);
        }
        
        return key;
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

        byte[]  dkey = generatederivedkey(keysize);

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

        byte[]  dkey = generatederivedkey(keysize + ivsize);

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
