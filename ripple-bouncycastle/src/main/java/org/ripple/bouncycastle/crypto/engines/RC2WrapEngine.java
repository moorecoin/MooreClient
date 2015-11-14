package org.ripple.bouncycastle.crypto.engines;

import java.security.securerandom;

import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.digest;
import org.ripple.bouncycastle.crypto.invalidciphertextexception;
import org.ripple.bouncycastle.crypto.wrapper;
import org.ripple.bouncycastle.crypto.digests.sha1digest;
import org.ripple.bouncycastle.crypto.modes.cbcblockcipher;
import org.ripple.bouncycastle.crypto.params.parameterswithiv;
import org.ripple.bouncycastle.crypto.params.parameterswithrandom;
import org.ripple.bouncycastle.util.arrays;

/**
 * wrap keys according to rfc 3217 - rc2 mechanism
 */
public class rc2wrapengine
    implements wrapper
{
   /** field engine */
   private cbcblockcipher engine;

   /** field param */
   private cipherparameters param;

   /** field paramplusiv */
   private parameterswithiv paramplusiv;

   /** field iv */
   private byte[] iv;

   /** field forwrapping */
   private boolean forwrapping;
   
   private securerandom sr;

   /** field iv2           */
   private static final byte[] iv2 = { (byte) 0x4a, (byte) 0xdd, (byte) 0xa2,
                                       (byte) 0x2c, (byte) 0x79, (byte) 0xe8,
                                       (byte) 0x21, (byte) 0x05 };

    //
    // checksum digest
    //
    digest  sha1 = new sha1digest();
    byte[]  digest = new byte[20];

   /**
    * method init
    *
    * @param forwrapping
    * @param param
    */
   public void init(boolean forwrapping, cipherparameters param)
   {
        this.forwrapping = forwrapping;
        this.engine = new cbcblockcipher(new rc2engine());

        if (param instanceof parameterswithrandom)
        {
            parameterswithrandom pwithr = (parameterswithrandom)param;
            sr = pwithr.getrandom();
            param = pwithr.getparameters();
        }
        else
        {
            sr = new securerandom();
        }
        
        if (param instanceof parameterswithiv)
        {
            this.paramplusiv = (parameterswithiv)param;
            this.iv = this.paramplusiv.getiv();
            this.param = this.paramplusiv.getparameters();

            if (this.forwrapping)
            {
                if ((this.iv == null) || (this.iv.length != 8))
                {
                    throw new illegalargumentexception("iv is not 8 octets");
                }
            }
            else
            {
                throw new illegalargumentexception(
                        "you should not supply an iv for unwrapping");
            }
        }
        else
        {
            this.param = param;

            if (this.forwrapping)
            {

                // hm, we have no iv but we want to wrap ?!?
                // well, then we have to create our own iv.
                this.iv = new byte[8];

                sr.nextbytes(iv);

                this.paramplusiv = new parameterswithiv(this.param, this.iv);
            }
        }

   }

   /**
    * method getalgorithmname
    *
    * @return the algorithm name "rc2".
    */
   public string getalgorithmname() 
   {
      return "rc2";
   }

   /**
    * method wrap
    *
    * @param in
    * @param inoff
    * @param inlen
    * @return the wrapped bytes.
    */
   public byte[] wrap(byte[] in, int inoff, int inlen)
    {

        if (!forwrapping)
        {
            throw new illegalstateexception("not initialized for wrapping");
        }

        int length = inlen + 1;
        if ((length % 8) != 0)
        {
            length += 8 - (length % 8);
        }

        byte keytobewrapped[] = new byte[length];

        keytobewrapped[0] = (byte)inlen;
        system.arraycopy(in, inoff, keytobewrapped, 1, inlen);
        
        byte[] pad = new byte[keytobewrapped.length - inlen - 1];

        if (pad.length > 0)
        {
            sr.nextbytes(pad);
            system.arraycopy(pad, 0, keytobewrapped, inlen + 1, pad.length);
        }

        // compute the cms key checksum, (section 5.6.1), call this cks.
        byte[] cks = calculatecmskeychecksum(keytobewrapped);

        // let wkcks = wk || cks where || is concatenation.
        byte[] wkcks = new byte[keytobewrapped.length + cks.length];

        system.arraycopy(keytobewrapped, 0, wkcks, 0, keytobewrapped.length);
        system.arraycopy(cks, 0, wkcks, keytobewrapped.length, cks.length);

        // encrypt wkcks in cbc mode using kek as the key and iv as the
        // initialization vector. call the results temp1.
        byte temp1[] = new byte[wkcks.length];

        system.arraycopy(wkcks, 0, temp1, 0, wkcks.length);

        int noofblocks = wkcks.length / engine.getblocksize();
        int extrabytes = wkcks.length % engine.getblocksize();

        if (extrabytes != 0)
        {
            throw new illegalstateexception("not multiple of block length");
        }

        engine.init(true, paramplusiv);

        for (int i = 0; i < noofblocks; i++)
        {
            int currentbytepos = i * engine.getblocksize();

            engine.processblock(temp1, currentbytepos, temp1, currentbytepos);
        }

        // left temp2 = iv || temp1.
        byte[] temp2 = new byte[this.iv.length + temp1.length];

        system.arraycopy(this.iv, 0, temp2, 0, this.iv.length);
        system.arraycopy(temp1, 0, temp2, this.iv.length, temp1.length);

        // reverse the order of the octets in temp2 and call the result temp3.
        byte[] temp3 = new byte[temp2.length];

        for (int i = 0; i < temp2.length; i++)
        {
            temp3[i] = temp2[temp2.length - (i + 1)];
        }

        // encrypt temp3 in cbc mode using the kek and an initialization vector
        // of 0x 4a dd a2 2c 79 e8 21 05. the resulting cipher text is the
        // desired
        // result. it is 40 octets long if a 168 bit key is being wrapped.
        parameterswithiv param2 = new parameterswithiv(this.param, iv2);

        this.engine.init(true, param2);

        for (int i = 0; i < noofblocks + 1; i++)
        {
            int currentbytepos = i * engine.getblocksize();

            engine.processblock(temp3, currentbytepos, temp3, currentbytepos);
        }

        return temp3;
   }

   /**
    * method unwrap
    *
    * @param in
    * @param inoff
    * @param inlen
    * @return the unwrapped bytes.
    * @throws invalidciphertextexception
    */
   public byte[] unwrap(byte[] in, int inoff, int inlen)
            throws invalidciphertextexception
    {

        if (forwrapping)
        {
            throw new illegalstateexception("not set for unwrapping");
        }

        if (in == null)
        {
            throw new invalidciphertextexception("null pointer as ciphertext");
        }

        if (inlen % engine.getblocksize() != 0)
        {
            throw new invalidciphertextexception("ciphertext not multiple of "
                    + engine.getblocksize());
        }

        /*
         * // check if the length of the cipher text is reasonable given the key //
         * type. it must be 40 bytes for a 168 bit key and either 32, 40, or //
         * 48 bytes for a 128, 192, or 256 bit key. if the length is not
         * supported // or inconsistent with the algorithm for which the key is
         * intended, // return error. // // we do not accept 168 bit keys. it
         * has to be 192 bit. int lengtha = (estimatedkeylengthinbit / 8) + 16;
         * int lengthb = estimatedkeylengthinbit % 8;
         * 
         * if ((lengtha != keytobeunwrapped.length) || (lengthb != 0)) { throw
         * new xmlsecurityexception("empty"); }
         */

        // decrypt the cipher text with tripledes in cbc mode using the kek
        // and an initialization vector (iv) of 0x4adda22c79e82105. call the
        // output temp3.
        parameterswithiv param2 = new parameterswithiv(this.param, iv2);

        this.engine.init(false, param2);

        byte temp3[] = new byte[inlen];

        system.arraycopy(in, inoff, temp3, 0, inlen);

        for (int i = 0; i < (temp3.length / engine.getblocksize()); i++)
        {
            int currentbytepos = i * engine.getblocksize();

            engine.processblock(temp3, currentbytepos, temp3, currentbytepos);
        }

        // reverse the order of the octets in temp3 and call the result temp2.
        byte[] temp2 = new byte[temp3.length];

        for (int i = 0; i < temp3.length; i++)
        {
            temp2[i] = temp3[temp3.length - (i + 1)];
        }

        // decompose temp2 into iv, the first 8 octets, and temp1, the remaining
        // octets.
        this.iv = new byte[8];

        byte[] temp1 = new byte[temp2.length - 8];

        system.arraycopy(temp2, 0, this.iv, 0, 8);
        system.arraycopy(temp2, 8, temp1, 0, temp2.length - 8);

        // decrypt temp1 using tripledes in cbc mode using the kek and the iv
        // found in the previous step. call the result wkcks.
        this.paramplusiv = new parameterswithiv(this.param, this.iv);

        this.engine.init(false, this.paramplusiv);

        byte[] lcekpadicv = new byte[temp1.length];

        system.arraycopy(temp1, 0, lcekpadicv, 0, temp1.length);

        for (int i = 0; i < (lcekpadicv.length / engine.getblocksize()); i++)
        {
            int currentbytepos = i * engine.getblocksize();

            engine.processblock(lcekpadicv, currentbytepos, lcekpadicv,
                    currentbytepos);
        }

        // decompose lcekpadicv. cks is the last 8 octets and wk, the wrapped
        // key, are
        // those octets before the cks.
        byte[] result = new byte[lcekpadicv.length - 8];
        byte[] ckstobeverified = new byte[8];

        system.arraycopy(lcekpadicv, 0, result, 0, lcekpadicv.length - 8);
        system.arraycopy(lcekpadicv, lcekpadicv.length - 8, ckstobeverified, 0,
                8);

        // calculate a cms key checksum, (section 5.6.1), over the wk and
        // compare
        // with the cks extracted in the above step. if they are not equal,
        // return error.
        if (!checkcmskeychecksum(result, ckstobeverified))
        {
            throw new invalidciphertextexception(
                    "checksum inside ciphertext is corrupted");
        }

        if ((result.length - ((result[0] & 0xff) + 1)) > 7)
        {
            throw new invalidciphertextexception("too many pad bytes ("
                    + (result.length - ((result[0] & 0xff) + 1)) + ")");
        }

        // cek is the wrapped key, now extracted for use in data decryption.
        byte[] cek = new byte[result[0]];
        system.arraycopy(result, 1, cek, 0, cek.length);
        return cek;
    }

    /**
     * some key wrap algorithms make use of the key checksum defined
     * in cms [cms-algorithms]. this is used to provide an integrity
     * check value for the key being wrapped. the algorithm is
     *
     * - compute the 20 octet sha-1 hash on the key being wrapped.
     * - use the first 8 octets of this hash as the checksum value.
     *
     * @param key
     * @return
     * @throws runtimeexception
     * @see http://www.w3.org/tr/xmlenc-core/#sec-cmskeychecksum
     */
    private byte[] calculatecmskeychecksum(
        byte[] key)
    {
        byte[]  result = new byte[8];

        sha1.update(key, 0, key.length);
        sha1.dofinal(digest, 0);

        system.arraycopy(digest, 0, result, 0, 8);

        return result;
    }

    /**
     * @param key
     * @param checksum
     * @return
     * @see http://www.w3.org/tr/xmlenc-core/#sec-cmskeychecksum
     */
    private boolean checkcmskeychecksum(
        byte[] key,
        byte[] checksum)
    {
        return arrays.constanttimeareequal(calculatecmskeychecksum(key), checksum);
    }
}
