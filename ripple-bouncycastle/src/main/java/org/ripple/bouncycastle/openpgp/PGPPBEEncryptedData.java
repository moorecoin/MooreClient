package org.ripple.bouncycastle.openpgp;

import java.io.eofexception;
import java.io.inputstream;
import java.security.nosuchproviderexception;
import java.security.provider;

import org.ripple.bouncycastle.bcpg.bcpginputstream;
import org.ripple.bouncycastle.bcpg.inputstreampacket;
import org.ripple.bouncycastle.bcpg.symmetricencintegritypacket;
import org.ripple.bouncycastle.bcpg.symmetrickeyencsessionpacket;
import org.ripple.bouncycastle.openpgp.operator.pbedatadecryptorfactory;
import org.ripple.bouncycastle.openpgp.operator.pgpdatadecryptor;
import org.ripple.bouncycastle.openpgp.operator.jcajce.jcapgpdigestcalculatorproviderbuilder;
import org.ripple.bouncycastle.openpgp.operator.jcajce.jcepbedatadecryptorfactorybuilder;
import org.ripple.bouncycastle.util.io.teeinputstream;

/**
 * a password based encryption object.
 */
public class pgppbeencrypteddata
    extends pgpencrypteddata
{
    symmetrickeyencsessionpacket    keydata;
    
    pgppbeencrypteddata(
        symmetrickeyencsessionpacket    keydata,
        inputstreampacket               encdata)
    {
        super(encdata);
        
        this.keydata = keydata;
    }
    
    /**
     * return the raw input stream for the data stream.
     * 
     * @return inputstream
     */
    public inputstream getinputstream()
    {
        return encdata.getinputstream();
    }

    /**
     * return the decrypted input stream, using the passed in passphrase.
     *
     * @param passphrase
     * @param provider
     * @return inputstream
     * @throws pgpexception
     * @throws nosuchproviderexception
     *  @deprecated use pbedatadecryptorfactory method
     */
    public inputstream getdatastream(
        char[]                passphrase,
        string                provider)
        throws pgpexception, nosuchproviderexception
    {
        return getdatastream(passphrase, pgputil.getprovider(provider));
    }

    /**
     * return the decrypted input stream, using the passed in passphrase.
     * 
     * @param passphrase
     * @param provider
     * @return inputstream
     * @throws pgpexception
     * @deprecated use pbedatadecryptorfactory method
     */
    public inputstream getdatastream(
        char[]                passphrase,
        provider              provider)
        throws pgpexception
    {
        return getdatastream(new jcepbedatadecryptorfactorybuilder(new jcapgpdigestcalculatorproviderbuilder().setprovider(provider).build()).setprovider(provider).build(passphrase));
    }

   /**
     * return the symmetric key algorithm required to decrypt the data protected by this object.
     *
     * @param datadecryptorfactory   decryptor factory to use to recover the session data.
     * @return  the integer encryption algorithm code.
     * @throws pgpexception if the session data cannot be recovered.
     */
    public int getsymmetricalgorithm(
        pbedatadecryptorfactory datadecryptorfactory)
        throws pgpexception
    {
        byte[]       key = datadecryptorfactory.makekeyfrompassphrase(keydata.getencalgorithm(), keydata.gets2k());
        byte[]       sessiondata = datadecryptorfactory.recoversessiondata(keydata.getencalgorithm(), key, keydata.getseckeydata());

        return sessiondata[0];
    }

   /**
     * open an input stream which will provide the decrypted data protected by this object.
     *
     * @param datadecryptorfactory  decryptor factory to use to recover the session data and provide the stream.
     * @return  the resulting input stream
     * @throws pgpexception  if the session data cannot be recovered or the stream cannot be created.
     */
    public inputstream getdatastream(
        pbedatadecryptorfactory datadecryptorfactory)
        throws pgpexception
    {
        try
        {
            int          keyalgorithm = keydata.getencalgorithm();
            byte[]       key = datadecryptorfactory.makekeyfrompassphrase(keyalgorithm, keydata.gets2k());
            boolean      withintegritypacket = encdata instanceof symmetricencintegritypacket;

            byte[]       sessiondata = datadecryptorfactory.recoversessiondata(keydata.getencalgorithm(), key, keydata.getseckeydata());
            byte[]       sessionkey = new byte[sessiondata.length - 1];

            system.arraycopy(sessiondata, 1, sessionkey, 0, sessionkey.length);

            pgpdatadecryptor datadecryptor = datadecryptorfactory.createdatadecryptor(withintegritypacket, sessiondata[0] & 0xff, sessionkey);

            encstream = new bcpginputstream(datadecryptor.getinputstream(encdata.getinputstream()));

            if (withintegritypacket)
            {
                truncstream = new truncatedstream(encstream);

                integritycalculator = datadecryptor.getintegritycalculator();

                encstream = new teeinputstream(truncstream, integritycalculator.getoutputstream());
            }

            byte[] iv = new byte[datadecryptor.getblocksize()];
            for (int i = 0; i != iv.length; i++)
            {
                int    ch = encstream.read();

                if (ch < 0)
                {
                    throw new eofexception("unexpected end of stream.");
                }

                iv[i] = (byte)ch;
            }

            int    v1 = encstream.read();
            int    v2 = encstream.read();

            if (v1 < 0 || v2 < 0)
            {
                throw new eofexception("unexpected end of stream.");
            }


            // note: the oracle attack on "quick check" bytes is not deemed
            // a security risk for pbe (see pgppublickeyencrypteddata)

            boolean repeatcheckpassed = iv[iv.length - 2] == (byte) v1
                    && iv[iv.length - 1] == (byte) v2;

            // note: some versions of pgp appear to produce 0 for the extra
            // bytes rather than repeating the two previous bytes
            boolean zeroescheckpassed = v1 == 0 && v2 == 0;

            if (!repeatcheckpassed && !zeroescheckpassed)
            {
                throw new pgpdatavalidationexception("data check failed.");
            }

            return encstream;
        }
        catch (pgpexception e)
        {
            throw e;
        }
        catch (exception e)
        {
            throw new pgpexception("exception creating cipher", e);
        }
    }
}
