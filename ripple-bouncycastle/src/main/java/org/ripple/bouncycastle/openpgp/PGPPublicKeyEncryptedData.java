package org.ripple.bouncycastle.openpgp;

import java.io.eofexception;
import java.io.inputstream;
import java.security.nosuchproviderexception;
import java.security.provider;

import org.ripple.bouncycastle.bcpg.bcpginputstream;
import org.ripple.bouncycastle.bcpg.inputstreampacket;
import org.ripple.bouncycastle.bcpg.publickeyencsessionpacket;
import org.ripple.bouncycastle.bcpg.symmetricencintegritypacket;
import org.ripple.bouncycastle.bcpg.symmetrickeyalgorithmtags;
import org.ripple.bouncycastle.openpgp.operator.pgpdatadecryptor;
import org.ripple.bouncycastle.openpgp.operator.publickeydatadecryptorfactory;
import org.ripple.bouncycastle.openpgp.operator.jcajce.jcepublickeydatadecryptorfactorybuilder;
import org.ripple.bouncycastle.util.io.teeinputstream;

/**
 * a public key encrypted data object.
 */
public class pgppublickeyencrypteddata
    extends pgpencrypteddata
{    
    publickeyencsessionpacket        keydata;
    
    pgppublickeyencrypteddata(
        publickeyencsessionpacket    keydata,
        inputstreampacket            encdata)
    {
        super(encdata);
        
        this.keydata = keydata;
    }

    private boolean confirmchecksum(
        byte[]    sessioninfo)
    {
        int    check = 0;
        
        for (int i = 1; i != sessioninfo.length - 2; i++)
        {
            check += sessioninfo[i] & 0xff;
        }
        
        return (sessioninfo[sessioninfo.length - 2] == (byte)(check >> 8))
                    && (sessioninfo[sessioninfo.length - 1] == (byte)(check));
    }
    
    /**
     * return the keyid for the key used to encrypt the data.
     * 
     * @return long
     */
    public long getkeyid()
    {
        return keydata.getkeyid();
    }

    /**
     * return the algorithm code for the symmetric algorithm used to encrypt the data.
     *
     * @return integer algorithm code
     * @deprecated use the method taking a publickeydatadecryptorfactory
     */
    public int getsymmetricalgorithm(
        pgpprivatekey  privkey,
        string         provider)
        throws pgpexception, nosuchproviderexception
    {
        return getsymmetricalgorithm(privkey, pgputil.getprovider(provider));
    }

    /**
     *
     * @deprecated use the method taking a publickeydatadecryptorfactory
     */
    public int getsymmetricalgorithm(
        pgpprivatekey  privkey,
        provider       provider)
        throws pgpexception, nosuchproviderexception
    {
        return getsymmetricalgorithm(new jcepublickeydatadecryptorfactorybuilder().setprovider(provider).setcontentprovider(provider).build(privkey));
    }

    /**
     * return the symmetric key algorithm required to decrypt the data protected by this object.
     *
     * @param datadecryptorfactory   decryptor factory to use to recover the session data.
     * @return  the integer encryption algorithm code.
     * @throws pgpexception if the session data cannot be recovered.
     */
    public int getsymmetricalgorithm(
        publickeydatadecryptorfactory datadecryptorfactory)
        throws pgpexception
    {
        byte[] plain = datadecryptorfactory.recoversessiondata(keydata.getalgorithm(), keydata.getencsessionkey());

        return plain[0];
    }

    /**
     * return the decrypted data stream for the packet.
     *
     * @param privkey private key to use
     * @param provider provider to use for private key and symmetric key decryption.
     * @return inputstream
     * @throws pgpexception
     * @throws nosuchproviderexception
     * @deprecated use method that takes a publickeydatadecryptorfactory
     */
    public inputstream getdatastream(
        pgpprivatekey  privkey,
        string         provider)
        throws pgpexception, nosuchproviderexception
    {
        return getdatastream(privkey, provider, provider);
    }

        /**
     *
     * @param privkey
     * @param provider
     * @return
     * @throws pgpexception
     *  @deprecated use method that takes a publickeydatadecryptorfactory
     */
    public inputstream getdatastream(
        pgpprivatekey  privkey,
        provider       provider)
        throws pgpexception
    {
        return getdatastream(privkey, provider, provider);
    }

    /**
     * return the decrypted data stream for the packet.
     * 
     * @param privkey private key to use.
     * @param asymprovider asymetric provider to use with private key.
     * @param provider provider to use for symmetric algorithm.
     * @return inputstream
     * @throws pgpexception
     * @throws nosuchproviderexception
     *  @deprecated use method that takes a publickeydatadecryptorfactory
     */
    public inputstream getdatastream(
        pgpprivatekey  privkey,
        string         asymprovider,
        string         provider)
        throws pgpexception, nosuchproviderexception
    {
        return getdatastream(privkey, pgputil.getprovider(asymprovider), pgputil.getprovider(provider));
    }

    /**
     *  @deprecated use method that takes a publickeydatadecryptorfactory
     */
    public inputstream getdatastream(
        pgpprivatekey  privkey,
        provider       asymprovider,
        provider       provider)
        throws pgpexception
    {
        return getdatastream(new jcepublickeydatadecryptorfactorybuilder().setprovider(asymprovider).setcontentprovider(provider).build(privkey));
    }

    /**
     * open an input stream which will provide the decrypted data protected by this object.
     *
     * @param datadecryptorfactory  decryptor factory to use to recover the session data and provide the stream.
     * @return  the resulting input stream
     * @throws pgpexception  if the session data cannot be recovered or the stream cannot be created.
     */
    public inputstream getdatastream(
        publickeydatadecryptorfactory datadecryptorfactory)
        throws pgpexception
    {
        byte[] sessiondata = datadecryptorfactory.recoversessiondata(keydata.getalgorithm(), keydata.getencsessionkey());

        if (!confirmchecksum(sessiondata))
        {
            throw new pgpkeyvalidationexception("key checksum failed");
        }

        if (sessiondata[0] != symmetrickeyalgorithmtags.null)
        {
            try
            {
                boolean      withintegritypacket = encdata instanceof symmetricencintegritypacket;
                byte[]       sessionkey = new byte[sessiondata.length - 3];

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

                //
                // some versions of pgp appear to produce 0 for the extra
                // bytes rather than repeating the two previous bytes
                //
                /*
                             * commented out in the light of the oracle attack.
                            if (iv[iv.length - 2] != (byte)v1 && v1 != 0)
                            {
                                throw new pgpdatavalidationexception("data check failed.");
                            }

                            if (iv[iv.length - 1] != (byte)v2 && v2 != 0)
                            {
                                throw new pgpdatavalidationexception("data check failed.");
                            }
                            */

                return encstream;
            }
            catch (pgpexception e)
            {
                throw e;
            }
            catch (exception e)
            {
                throw new pgpexception("exception starting decryption", e);
            }
        }
        else
        {
            return encdata.getinputstream();
        }
    }
}
