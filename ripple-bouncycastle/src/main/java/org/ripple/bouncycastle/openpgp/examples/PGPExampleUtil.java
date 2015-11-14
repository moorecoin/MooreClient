package org.ripple.bouncycastle.openpgp.examples;

import java.io.bufferedinputstream;
import java.io.bytearrayoutputstream;
import java.io.file;
import java.io.fileinputstream;
import java.io.ioexception;
import java.io.inputstream;
import java.security.nosuchproviderexception;
import java.util.iterator;

import org.ripple.bouncycastle.openpgp.pgpcompresseddatagenerator;
import org.ripple.bouncycastle.openpgp.pgpexception;
import org.ripple.bouncycastle.openpgp.pgpliteraldata;
import org.ripple.bouncycastle.openpgp.pgpprivatekey;
import org.ripple.bouncycastle.openpgp.pgppublickey;
import org.ripple.bouncycastle.openpgp.pgppublickeyring;
import org.ripple.bouncycastle.openpgp.pgppublickeyringcollection;
import org.ripple.bouncycastle.openpgp.pgpsecretkey;
import org.ripple.bouncycastle.openpgp.pgpsecretkeyring;
import org.ripple.bouncycastle.openpgp.pgpsecretkeyringcollection;
import org.ripple.bouncycastle.openpgp.pgputil;

class pgpexampleutil
{
    static byte[] compressfile(string filename, int algorithm) throws ioexception
    {
        bytearrayoutputstream bout = new bytearrayoutputstream();
        pgpcompresseddatagenerator comdata = new pgpcompresseddatagenerator(algorithm);
        pgputil.writefiletoliteraldata(comdata.open(bout), pgpliteraldata.binary,
            new file(filename));
        comdata.close();
        return bout.tobytearray();
    }

    /**
     * search a secret key ring collection for a secret key corresponding to keyid if it
     * exists.
     * 
     * @param pgpsec a secret key ring collection.
     * @param keyid keyid we want.
     * @param pass passphrase to decrypt secret key with.
     * @return
     * @throws pgpexception
     * @throws nosuchproviderexception
     */
    static pgpprivatekey findsecretkey(pgpsecretkeyringcollection pgpsec, long keyid, char[] pass)
        throws pgpexception, nosuchproviderexception
    {
        pgpsecretkey pgpseckey = pgpsec.getsecretkey(keyid);

        if (pgpseckey == null)
        {
            return null;
        }

        return pgpseckey.extractprivatekey(pass, "bc");
    }

    static pgppublickey readpublickey(string filename) throws ioexception, pgpexception
    {
        inputstream keyin = new bufferedinputstream(new fileinputstream(filename));
        pgppublickey pubkey = readpublickey(keyin);
        keyin.close();
        return pubkey;
    }

    /**
     * a simple routine that opens a key ring file and loads the first available key
     * suitable for encryption.
     * 
     * @param input
     * @return
     * @throws ioexception
     * @throws pgpexception
     */
    static pgppublickey readpublickey(inputstream input) throws ioexception, pgpexception
    {
        pgppublickeyringcollection pgppub = new pgppublickeyringcollection(
            pgputil.getdecoderstream(input));

        //
        // we just loop through the collection till we find a key suitable for encryption, in the real
        // world you would probably want to be a bit smarter about this.
        //

        iterator keyringiter = pgppub.getkeyrings();
        while (keyringiter.hasnext())
        {
            pgppublickeyring keyring = (pgppublickeyring)keyringiter.next();

            iterator keyiter = keyring.getpublickeys();
            while (keyiter.hasnext())
            {
                pgppublickey key = (pgppublickey)keyiter.next();

                if (key.isencryptionkey())
                {
                    return key;
                }
            }
        }

        throw new illegalargumentexception("can't find encryption key in key ring.");
    }

    static pgpsecretkey readsecretkey(string filename) throws ioexception, pgpexception
    {
        inputstream keyin = new bufferedinputstream(new fileinputstream(filename));
        pgpsecretkey seckey = readsecretkey(keyin);
        keyin.close();
        return seckey;
    }

    /**
     * a simple routine that opens a key ring file and loads the first available key
     * suitable for signature generation.
     * 
     * @param input stream to read the secret key ring collection from.
     * @return a secret key.
     * @throws ioexception on a problem with using the input stream.
     * @throws pgpexception if there is an issue parsing the input stream.
     */
    static pgpsecretkey readsecretkey(inputstream input) throws ioexception, pgpexception
    {
        pgpsecretkeyringcollection pgpsec = new pgpsecretkeyringcollection(
            pgputil.getdecoderstream(input));

        //
        // we just loop through the collection till we find a key suitable for encryption, in the real
        // world you would probably want to be a bit smarter about this.
        //

        iterator keyringiter = pgpsec.getkeyrings();
        while (keyringiter.hasnext())
        {
            pgpsecretkeyring keyring = (pgpsecretkeyring)keyringiter.next();

            iterator keyiter = keyring.getsecretkeys();
            while (keyiter.hasnext())
            {
                pgpsecretkey key = (pgpsecretkey)keyiter.next();

                if (key.issigningkey())
                {
                    return key;
                }
            }
        }

        throw new illegalargumentexception("can't find signing key in key ring.");
    }
}
