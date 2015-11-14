package org.ripple.bouncycastle.openpgp.examples;

import java.io.bytearrayinputstream;
import java.io.bytearrayoutputstream;
import java.io.ioexception;
import java.io.inputstream;
import java.io.outputstream;
import java.security.nosuchproviderexception;
import java.security.securerandom;
import java.security.security;
import java.util.date;

import org.ripple.bouncycastle.bcpg.armoredoutputstream;
import org.ripple.bouncycastle.bcpg.compressionalgorithmtags;
import org.ripple.bouncycastle.jce.provider.bouncycastleprovider;
import org.ripple.bouncycastle.openpgp.pgpcompresseddata;
import org.ripple.bouncycastle.openpgp.pgpcompresseddatagenerator;
import org.ripple.bouncycastle.openpgp.pgpencrypteddatagenerator;
import org.ripple.bouncycastle.openpgp.pgpencrypteddatalist;
import org.ripple.bouncycastle.openpgp.pgpexception;
import org.ripple.bouncycastle.openpgp.pgpliteraldata;
import org.ripple.bouncycastle.openpgp.pgpliteraldatagenerator;
import org.ripple.bouncycastle.openpgp.pgpobjectfactory;
import org.ripple.bouncycastle.openpgp.pgppbeencrypteddata;
import org.ripple.bouncycastle.openpgp.pgputil;
import org.ripple.bouncycastle.openpgp.operator.jcajce.jcapgpdigestcalculatorproviderbuilder;
import org.ripple.bouncycastle.openpgp.operator.jcajce.jcepbedatadecryptorfactorybuilder;
import org.ripple.bouncycastle.openpgp.operator.jcajce.jcepbekeyencryptionmethodgenerator;
import org.ripple.bouncycastle.openpgp.operator.jcajce.jcepgpdataencryptorbuilder;
import org.ripple.bouncycastle.util.io.streams;

/**
 * simple routine to encrypt and decrypt using a passphrase.
 * this service routine provides the basic pgp services between
 * byte arrays.
 * 
 * note: this code plays no attention to -console in the file name
 * the specification of "_console" in the filename.
 * it also expects that a single pass phrase will have been used.
 * 
 */
public class bytearrayhandler
{
    /**
     * decrypt the passed in message stream
     * 
     * @param encrypted  the message to be decrypted.
     * @param passphrase pass phrase (key)
     * 
     * @return clear text as a byte array.  i18n considerations are
     *         not handled by this routine
     * @exception ioexception
     * @exception pgpexception
     * @exception nosuchproviderexception
     */
    public static byte[] decrypt(
        byte[] encrypted,
        char[] passphrase)
        throws ioexception, pgpexception, nosuchproviderexception
    {
        inputstream in = new bytearrayinputstream(encrypted);

        in = pgputil.getdecoderstream(in);

        pgpobjectfactory         pgpf = new pgpobjectfactory(in);
        pgpencrypteddatalist     enc;
        object                          o = pgpf.nextobject();
        
        //
        // the first object might be a pgp marker packet.
        //
        if (o instanceof pgpencrypteddatalist)
        {
            enc = (pgpencrypteddatalist)o;
        }
        else
        {
            enc = (pgpencrypteddatalist)pgpf.nextobject();
        }

        pgppbeencrypteddata pbe = (pgppbeencrypteddata)enc.get(0);

        inputstream clear = pbe.getdatastream(new jcepbedatadecryptorfactorybuilder(new jcapgpdigestcalculatorproviderbuilder().setprovider("bc").build()).setprovider("bc").build(passphrase));

        pgpobjectfactory        pgpfact = new pgpobjectfactory(clear);

        pgpcompresseddata   cdata = (pgpcompresseddata)pgpfact.nextobject();

        pgpfact = new pgpobjectfactory(cdata.getdatastream());

        pgpliteraldata ld = (pgpliteraldata)pgpfact.nextobject();

        return streams.readall(ld.getinputstream());
    }

    /**
     * simple pgp encryptor between byte[].
     * 
     * @param cleardata  the test to be encrypted
     * @param passphrase the pass phrase (key).  this method assumes that the
     *                   key is a simple pass phrase, and does not yet support
     *                   rsa or more sophisiticated keying.
     * @param filename   file name. this is used in the literal data packet (tag 11)
     *                   which is really inly important if the data is to be
     *                   related to a file to be recovered later.  because this
     *                   routine does not know the source of the information, the
     *                   caller can set something here for file name use that
     *                   will be carried.  if this routine is being used to
     *                   encrypt soap mime bodies, for example, use the file name from the
     *                   mime type, if applicable. or anything else appropriate.
     *                             
     * @param armor
     * 
     * @return encrypted data.
     * @exception ioexception
     * @exception pgpexception
     * @exception nosuchproviderexception
     */
    public static byte[] encrypt(
        byte[]  cleardata,
        char[]  passphrase,
        string  filename,
        int     algorithm,
        boolean armor)
        throws ioexception, pgpexception, nosuchproviderexception
    {
        if (filename == null)
        {
            filename= pgpliteraldata.console;
        }

        byte[] compresseddata = compress(cleardata, filename, compressionalgorithmtags.zip);

        bytearrayoutputstream bout = new bytearrayoutputstream();

        outputstream out = bout;
        if (armor)
        {
            out = new armoredoutputstream(out);
        }

        pgpencrypteddatagenerator encgen = new pgpencrypteddatagenerator(new jcepgpdataencryptorbuilder(algorithm).setsecurerandom(new securerandom()).setprovider("bc"));
        encgen.addmethod(new jcepbekeyencryptionmethodgenerator(passphrase).setprovider("bc"));

        outputstream encout = encgen.open(out, compresseddata.length);

        encout.write(compresseddata);
        encout.close();

        if (armor)
        {
            out.close();
        }

        return bout.tobytearray();
    }

    private static byte[] compress(byte[] cleardata, string filename, int algorithm) throws ioexception
    {
        bytearrayoutputstream bout = new bytearrayoutputstream();
        pgpcompresseddatagenerator comdata = new pgpcompresseddatagenerator(algorithm);
        outputstream cos = comdata.open(bout); // open it with the final destination

        pgpliteraldatagenerator ldata = new pgpliteraldatagenerator();

        // we want to generate compressed data. this might be a user option later,
        // in which case we would pass in bout.
        outputstream  pout = ldata.open(cos, // the compressed output stream
                                        pgpliteraldata.binary,
                                        filename,  // "filename" to store
                                        cleardata.length, // length of clear data
                                        new date()  // current time
                                      );

        pout.write(cleardata);
        pout.close();

        comdata.close();

        return bout.tobytearray();
    }

    public static void main(string[] args) throws exception
    {
        security.addprovider(new bouncycastleprovider());
        
        string passphrase = "dick beck";
        char[] passarray = passphrase.tochararray();

        byte[] original = "hello world".getbytes();
        system.out.println("starting pgp test");
        byte[] encrypted = encrypt(original, passarray, "iway", pgpencrypteddatagenerator.cast5, true);

        system.out.println("\nencrypted data = '"+new string(encrypted)+"'");
        byte[] decrypted= decrypt(encrypted,passarray);

        system.out.println("\ndecrypted data = '"+new string(decrypted)+"'");
        
        encrypted = encrypt(original, passarray, "iway", pgpencrypteddatagenerator.aes_256, false);

        system.out.println("\nencrypted data = '"+new string(org.ripple.bouncycastle.util.encoders.hex.encode(encrypted))+"'");
        decrypted= decrypt(encrypted, passarray);

        system.out.println("\ndecrypted data = '"+new string(decrypted)+"'");
    }
}
