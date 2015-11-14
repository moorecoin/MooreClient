package org.ripple.bouncycastle.crypto.engines;

import java.math.biginteger;
import java.util.vector;

import org.ripple.bouncycastle.crypto.asymmetricblockcipher;
import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.datalengthexception;
import org.ripple.bouncycastle.crypto.invalidciphertextexception;
import org.ripple.bouncycastle.crypto.params.naccachesternkeyparameters;
import org.ripple.bouncycastle.crypto.params.naccachesternprivatekeyparameters;
import org.ripple.bouncycastle.crypto.params.parameterswithrandom;
import org.ripple.bouncycastle.util.arrays;

/**
 * naccachestern engine. for details on this cipher, please see
 * http://www.gemplus.com/smart/rd/publications/pdf/ns98pkcs.pdf
 */
public class naccachesternengine
    implements asymmetricblockcipher
{
    private boolean forencryption;

    private naccachesternkeyparameters key;

    private vector[] lookup = null;

    private boolean debug = false;

    private static biginteger zero = biginteger.valueof(0);
    private static biginteger one = biginteger.valueof(1);

    /**
     * initializes this algorithm. must be called before all other functions.
     * 
     * @see org.ripple.bouncycastle.crypto.asymmetricblockcipher#init(boolean,
     *      org.ripple.bouncycastle.crypto.cipherparameters)
     */
    public void init(boolean forencryption, cipherparameters param)
    {
        this.forencryption = forencryption;

        if (param instanceof parameterswithrandom)
        {
            param = ((parameterswithrandom) param).getparameters();
        }

        key = (naccachesternkeyparameters)param;

        // construct lookup table for faster decryption if necessary
        if (!this.forencryption)
        {
            if (debug)
            {
                system.out.println("constructing lookup array");
            }
            naccachesternprivatekeyparameters priv = (naccachesternprivatekeyparameters)key;
            vector primes = priv.getsmallprimes();
            lookup = new vector[primes.size()];
            for (int i = 0; i < primes.size(); i++)
            {
                biginteger actualprime = (biginteger)primes.elementat(i);
                int actualprimevalue = actualprime.intvalue();

                lookup[i] = new vector();
                lookup[i].addelement(one);

                if (debug)
                {
                    system.out.println("constructing lookup arraylist for " + actualprimevalue);
                }

                biginteger accj = zero;

                for (int j = 1; j < actualprimevalue; j++)
                {
                    accj = accj.add(priv.getphi_n());
                    biginteger comp = accj.divide(actualprime);
                    lookup[i].addelement(priv.getg().modpow(comp, priv.getmodulus()));
                }
            }
        }
    }

    public void setdebug(boolean debug)
    {
        this.debug = debug;
    }

    /**
     * returns the input block size of this algorithm.
     * 
     * @see org.ripple.bouncycastle.crypto.asymmetricblockcipher#getinputblocksize()
     */
    public int getinputblocksize()
    {
        if (forencryption)
        {
            // we can only encrypt values up to lowersigmabound
            return (key.getlowersigmabound() + 7) / 8 - 1;
        }
        else
        {
            // we pad to modulus-size bytes for easier decryption.
            return key.getmodulus().tobytearray().length;
        }
    }

    /**
     * returns the output block size of this algorithm.
     * 
     * @see org.ripple.bouncycastle.crypto.asymmetricblockcipher#getoutputblocksize()
     */
    public int getoutputblocksize()
    {
        if (forencryption)
        {
            // encrypted data is always padded up to modulus size
            return key.getmodulus().tobytearray().length;
        }
        else
        {
            // decrypted data has upper limit lowersigmabound
            return (key.getlowersigmabound() + 7) / 8 - 1;
        }
    }

    /**
     * process a single block using the naccache-stern algorithm.
     * 
     * @see org.ripple.bouncycastle.crypto.asymmetricblockcipher#processblock(byte[],
     *      int, int)
     */
    public byte[] processblock(byte[] in, int inoff, int len) throws invalidciphertextexception
    {
        if (key == null)
        {
            throw new illegalstateexception("naccachestern engine not initialised");
        }
        if (len > (getinputblocksize() + 1))
        {
            throw new datalengthexception("input too large for naccache-stern cipher.\n");
        }

        if (!forencryption)
        {
            // at decryption make sure that we receive padded data blocks
            if (len < getinputblocksize())
            {
                throw new invalidciphertextexception("blocklength does not match modulus for naccache-stern cipher.\n");
            }
        }

        byte[] block;

        if (inoff != 0 || len != in.length)
        {
            block = new byte[len];
            system.arraycopy(in, inoff, block, 0, len);
        }
        else
        {
            block = in;
        }

        // transform input into biginteger
        biginteger input = new biginteger(1, block);
        if (debug)
        {
            system.out.println("input as biginteger: " + input);
        }
        byte[] output;
        if (forencryption)
        {
            output = encrypt(input);
        }
        else
        {
            vector plain = new vector();
            naccachesternprivatekeyparameters priv = (naccachesternprivatekeyparameters)key;
            vector primes = priv.getsmallprimes();
            // get chinese remainders of ciphertext
            for (int i = 0; i < primes.size(); i++)
            {
                biginteger exp = input.modpow(priv.getphi_n().divide((biginteger)primes.elementat(i)), priv.getmodulus());
                vector al = lookup[i];
                if (lookup[i].size() != ((biginteger)primes.elementat(i)).intvalue())
                {
                    if (debug)
                    {
                        system.out.println("prime is " + primes.elementat(i) + ", lookup table has size " + al.size());
                    }
                    throw new invalidciphertextexception("error in lookup array for "
                                    + ((biginteger)primes.elementat(i)).intvalue()
                                    + ": size mismatch. expected arraylist with length "
                                    + ((biginteger)primes.elementat(i)).intvalue() + " but found arraylist of length "
                                    + lookup[i].size());
                }
                int lookedup = al.indexof(exp);

                if (lookedup == -1)
                {
                    if (debug)
                    {
                        system.out.println("actual prime is " + primes.elementat(i));
                        system.out.println("decrypted value is " + exp);

                        system.out.println("lookuplist for " + primes.elementat(i) + " with size " + lookup[i].size()
                                        + " is: ");
                        for (int j = 0; j < lookup[i].size(); j++)
                        {
                            system.out.println(lookup[i].elementat(j));
                        }
                    }
                    throw new invalidciphertextexception("lookup failed");
                }
                plain.addelement(biginteger.valueof(lookedup));
            }
            biginteger test = chineseremainder(plain, primes);

            // should not be used as an oracle, so reencrypt output to see
            // if it corresponds to input

            // this breaks probabilisic encryption, so disable it. anyway, we do
            // use the first n primes for key generation, so it is pretty easy
            // to guess them. but as stated in the paper, this is not a security
            // breach. so we can just work with the correct sigma.

            // if (debug) {
            //      system.out.println("decryption is " + test);
            // }
            // if ((key.getg().modpow(test, key.getmodulus())).equals(input)) {
            //      output = test.tobytearray();
            // } else {
            //      if(debug){
            //          system.out.println("engine seems to be used as an oracle,
            //          returning null");
            //      }
            //      output = null;
            // }

            output = test.tobytearray();

        }

        return output;
    }

    /**
     * encrypts a biginteger aka plaintext with the public key.
     * 
     * @param plain
     *            the biginteger to encrypt
     * @return the byte[] representation of the encrypted biginteger (i.e.
     *         crypted.tobytearray())
     */
    public byte[] encrypt(biginteger plain)
    {
        // always return modulus size values 0-padded at the beginning
        // 0-padding at the beginning is correctly parsed by biginteger :)
        byte[] output = key.getmodulus().tobytearray();
        arrays.fill(output, (byte)0);
        byte[] tmp = key.getg().modpow(plain, key.getmodulus()).tobytearray();
        system
                .arraycopy(tmp, 0, output, output.length - tmp.length,
                        tmp.length);
        if (debug)
        {
            system.out
                    .println("encrypted value is:  " + new biginteger(output));
        }
        return output;
    }

    /**
     * adds the contents of two encrypted blocks mod sigma
     * 
     * @param block1
     *            the first encrypted block
     * @param block2
     *            the second encrypted block
     * @return encrypt((block1 + block2) mod sigma)
     * @throws invalidciphertextexception
     */
    public byte[] addcryptedblocks(byte[] block1, byte[] block2)
            throws invalidciphertextexception
    {
        // check for correct blocksize
        if (forencryption)
        {
            if ((block1.length > getoutputblocksize())
                    || (block2.length > getoutputblocksize()))
            {
                throw new invalidciphertextexception(
                        "blocklength too large for simple addition.\n");
            }
        }
        else
        {
            if ((block1.length > getinputblocksize())
                    || (block2.length > getinputblocksize()))
            {
                throw new invalidciphertextexception(
                        "blocklength too large for simple addition.\n");
            }
        }

        // calculate resulting block
        biginteger m1crypt = new biginteger(1, block1);
        biginteger m2crypt = new biginteger(1, block2);
        biginteger m1m2crypt = m1crypt.multiply(m2crypt);
        m1m2crypt = m1m2crypt.mod(key.getmodulus());
        if (debug)
        {
            system.out.println("c(m1) as biginteger:....... " + m1crypt);
            system.out.println("c(m2) as biginteger:....... " + m2crypt);
            system.out.println("c(m1)*c(m2)%n = c(m1+m2)%n: " + m1m2crypt);
        }

        byte[] output = key.getmodulus().tobytearray();
        arrays.fill(output, (byte)0);
        system.arraycopy(m1m2crypt.tobytearray(), 0, output, output.length
                - m1m2crypt.tobytearray().length,
                m1m2crypt.tobytearray().length);

        return output;
    }

    /**
     * convenience method for data exchange with the cipher.
     * 
     * determines blocksize and splits data to blocksize.
     *
     * @param data the data to be processed
     * @return the data after it went through the naccachesternengine.
     * @throws invalidciphertextexception 
     */
    public byte[] processdata(byte[] data) throws invalidciphertextexception
    {
        if (debug)
        {
            system.out.println();
        }
        if (data.length > getinputblocksize())
        {
            int inblocksize = getinputblocksize();
            int outblocksize = getoutputblocksize();
            if (debug)
            {
                system.out.println("input blocksize is:  " + inblocksize + " bytes");
                system.out.println("output blocksize is: " + outblocksize + " bytes");
                system.out.println("data has length:.... " + data.length + " bytes");
            }
            int datapos = 0;
            int retpos = 0;
            byte[] retval = new byte[(data.length / inblocksize + 1) * outblocksize];
            while (datapos < data.length)
            {
                byte[] tmp;
                if (datapos + inblocksize < data.length)
                {
                    tmp = processblock(data, datapos, inblocksize);
                    datapos += inblocksize;
                }
                else
                {
                    tmp = processblock(data, datapos, data.length - datapos);
                    datapos += data.length - datapos;
                }
                if (debug)
                {
                    system.out.println("new datapos is " + datapos);
                }
                if (tmp != null)
                {
                    system.arraycopy(tmp, 0, retval, retpos, tmp.length);
                    
                    retpos += tmp.length;
                }
                else
                {
                    if (debug)
                    {
                        system.out.println("cipher returned null");
                    }
                    throw new invalidciphertextexception("cipher returned null");
                }
            }
            byte[] ret = new byte[retpos];
            system.arraycopy(retval, 0, ret, 0, retpos);
            if (debug)
            {
                system.out.println("returning " + ret.length + " bytes");
            }
            return ret;
        }
        else
        {
            if (debug)
            {
                system.out.println("data size is less then input block size, processing directly");
            }
            return processblock(data, 0, data.length);
        }
    }

    /**
     * computes the integer x that is expressed through the given primes and the
     * congruences with the chinese remainder theorem (crt).
     * 
     * @param congruences
     *            the congruences c_i
     * @param primes
     *            the primes p_i
     * @return an integer x for that x % p_i == c_i
     */
    private static biginteger chineseremainder(vector congruences, vector primes)
    {
        biginteger retval = zero;
        biginteger all = one;
        for (int i = 0; i < primes.size(); i++)
        {
            all = all.multiply((biginteger)primes.elementat(i));
        }
        for (int i = 0; i < primes.size(); i++)
        {
            biginteger a = (biginteger)primes.elementat(i);
            biginteger b = all.divide(a);
            biginteger b_ = b.modinverse(a);
            biginteger tmp = b.multiply(b_);
            tmp = tmp.multiply((biginteger)congruences.elementat(i));
            retval = retval.add(tmp);
        }

        return retval.mod(all);
    }
}
