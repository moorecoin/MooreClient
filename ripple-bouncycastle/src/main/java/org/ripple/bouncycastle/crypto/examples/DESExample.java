package org.ripple.bouncycastle.crypto.examples;

import java.io.bufferedinputstream;
import java.io.bufferedoutputstream;
import java.io.bufferedreader;
import java.io.fileinputstream;
import java.io.filenotfoundexception;
import java.io.fileoutputstream;
import java.io.ioexception;
import java.io.inputstreamreader;
import java.security.securerandom;

import org.ripple.bouncycastle.crypto.cryptoexception;
import org.ripple.bouncycastle.crypto.keygenerationparameters;
import org.ripple.bouncycastle.crypto.engines.desedeengine;
import org.ripple.bouncycastle.crypto.generators.desedekeygenerator;
import org.ripple.bouncycastle.crypto.modes.cbcblockcipher;
import org.ripple.bouncycastle.crypto.paddings.paddedbufferedblockcipher;
import org.ripple.bouncycastle.crypto.params.desedeparameters;
import org.ripple.bouncycastle.crypto.params.keyparameter;
import org.ripple.bouncycastle.util.encoders.hex;

/**
 * desexample is a simple des based encryptor/decryptor.
 * <p>
 * the program is command line driven, with the input
 * and output files specified on the command line.
 * <pre>
 * java org.bouncycastle.crypto.examples.desexample infile outfile [keyfile]
 * </pre>
 * a new key is generated for each encryption, if key is not specified,
 * then the example will assume encryption is required, and as output
 * create deskey.dat in the current directory.  this key is a hex
 * encoded byte-stream that is used for the decryption.  the output
 * file is hex encoded, 60 characters wide text file.
 * <p>
 * when encrypting;
 * <ul>
 *  <li>the infile is expected to be a byte stream (text or binary)
 *  <li>there is no keyfile specified on the input line
 * </ul>
 * <p>
 * when decrypting;
 *  <li>the infile is expected to be the 60 character wide base64 
 *    encoded file
 *  <li>the keyfile is expected to be a base64 encoded file
 * <p>
 * this example shows how to use the light-weight api, des and
 * the filesystem for message encryption and decryption.
 *
 */
public class desexample extends object
{
    // encrypting or decrypting ?
    private boolean encrypt = true;

    // to hold the initialised desede cipher
    private paddedbufferedblockcipher cipher = null;

    // the input stream of bytes to be processed for encryption
    private bufferedinputstream in = null;

    // the output stream of bytes to be procssed
    private bufferedoutputstream out = null;

    // the key
    private byte[] key = null;

    /*
     * start the application
     */
    public static void main(string[] args)
    {
        boolean encrypt = true;
        string infile = null;
        string outfile = null;
        string keyfile = null;

        if (args.length < 2)
        {
            desexample de = new desexample();
            system.err.println("usage: java "+de.getclass().getname()+
                                " infile outfile [keyfile]");
            system.exit(1);
        }

        keyfile = "deskey.dat";
        infile = args[0];
        outfile = args[1];

        if (args.length > 2)
        {
            encrypt = false;
            keyfile = args[2];
        }

        desexample de = new desexample(infile, outfile, keyfile, encrypt);
        de.process();
    }

    // default constructor, used for the usage message
    public desexample()
    {
    }

    /*
     * constructor, that takes the arguments appropriate for
     * processing the command line directives.
     */
    public desexample(
                string infile,
                string outfile,
                string keyfile,
                boolean encrypt)
    {
        /* 
         * first, determine that infile & keyfile exist as appropriate.
         *
         * this will also create the bufferedinputstream as required
         * for reading the input file.  all input files are treated
         * as if they are binary, even if they contain text, it's the
         * bytes that are encrypted.
         */
        this.encrypt = encrypt;
        try
        {
            in = new bufferedinputstream(new fileinputstream(infile));
        }
        catch (filenotfoundexception fnf)
        {
            system.err.println("input file not found ["+infile+"]");
            system.exit(1);
        }

        try
        {
            out = new bufferedoutputstream(new fileoutputstream(outfile));
        }
        catch (ioexception fnf)
        {
            system.err.println("output file not created ["+outfile+"]");
            system.exit(1);
        }

        if (encrypt)
        {
            try
            {
                /*
                 * the process of creating a new key requires a 
                 * number of steps.
                 *
                 * first, create the parameters for the key generator
                 * which are a secure random number generator, and
                 * the length of the key (in bits).
                 */
                securerandom sr = null;
                try
                {
                    sr = new securerandom();
                    /*
                     * this following call to setseed() makes the
                     * initialisation of the securerandom object
                     * _very_ fast, but not secure at all.  
                     *
                     * remove the line, recreate the class file and 
                     * then run desexample again to see the difference.
                     *
                     * the initialisation of a securerandom object
                     * can take 5 or more seconds depending on the
                     * cpu that the program is running on.  that can
                     * be annoying during unit testing.
                     *     -- jon
                     */
                    sr.setseed("www.bouncycastle.org".getbytes());
                }
                catch (exception nsa)
                {
                    system.err.println("hmmm, no sha1prng, you need the "+
                                        "sun implementation");
                    system.exit(1);
                }
                keygenerationparameters kgp = new keygenerationparameters(
                                    sr, 
                                    desedeparameters.des_ede_key_length*8);

                /*
                 * second, initialise the key generator with the parameters
                 */
                desedekeygenerator kg = new desedekeygenerator();
                kg.init(kgp);

                /*
                 * third, and finally, generate the key
                 */
                key = kg.generatekey();

                /*
                 * we can now output the key to the file, but first
                 * hex encode the key so that we can have a look
                 * at it with a text editor if we so desire
                 */
                bufferedoutputstream keystream = 
                    new bufferedoutputstream(new fileoutputstream(keyfile));
                byte[] keyhex = hex.encode(key);
                keystream.write(keyhex, 0, keyhex.length);
                keystream.flush();
                keystream.close();
            }
            catch (ioexception createkey)
            {
                system.err.println("could not decryption create key file "+
                                    "["+keyfile+"]");
                system.exit(1);
            }
        }
        else
        {
            try
            {
                // read the key, and decode from hex encoding
                bufferedinputstream keystream = 
                    new bufferedinputstream(new fileinputstream(keyfile));
                int len = keystream.available();
                byte[] keyhex = new byte[len];
                keystream.read(keyhex, 0, len);
                key = hex.decode(keyhex);
            }
            catch (ioexception ioe)
            {
                system.err.println("decryption key file not found, "+
                                    "or not valid ["+keyfile+"]");
                system.exit(1);
            }
        }
    }

    private void process()
    {
        /* 
         * setup the desede cipher engine, create a paddedbufferedblockcipher
         * in cbc mode.
         */
        cipher = new paddedbufferedblockcipher(
                                    new cbcblockcipher(new desedeengine()));

        /*
         * the input and output streams are currently set up
         * appropriately, and the key bytes are ready to be
         * used.
         *
         */

        if (encrypt)
        {
            performencrypt(key);
        }
        else
        {
            performdecrypt(key);
        }

        // after processing clean up the files
        try
        {
            in.close();
            out.flush();
            out.close();
        }
        catch (ioexception closing)
        {

        }
    }
        
    /*
     * this method performs all the encryption and writes
     * the cipher text to the buffered output stream created
     * previously.
     */
    private void performencrypt(byte[] key)
    {
        // initialise the cipher with the key bytes, for encryption
        cipher.init(true, new keyparameter(key));

        /*
         * create some temporary byte arrays for use in
         * encryption, make them a reasonable size so that
         * we don't spend forever reading small chunks from
         * a file.
         *
         * there is no particular reason for using getblocksize()
         * to determine the size of the input chunk.  it just
         * was a convenient number for the example.  
         */
        // int inblocksize = cipher.getblocksize() * 5;
        int inblocksize = 47;
        int outblocksize = cipher.getoutputsize(inblocksize);

        byte[] inblock = new byte[inblocksize];
        byte[] outblock = new byte[outblocksize];

        /* 
         * now, read the file, and output the chunks
         */
        try
        {
            int inl;
            int outl;
            byte[] rv = null;
            while ((inl=in.read(inblock, 0, inblocksize)) > 0)
            {
                outl = cipher.processbytes(inblock, 0, inl, outblock, 0);
                /*
                 * before we write anything out, we need to make sure
                 * that we've got something to write out. 
                 */
                if (outl > 0)
                {
                    rv = hex.encode(outblock, 0, outl);
                    out.write(rv, 0, rv.length);
                    out.write('\n');
                }
            }

            try
            {
                /*
                 * now, process the bytes that are still buffered
                 * within the cipher.
                 */
                outl = cipher.dofinal(outblock, 0);
                if (outl > 0)
                {
                    rv = hex.encode(outblock, 0, outl);
                    out.write(rv, 0, rv.length);
                    out.write('\n');
                }
            }
            catch (cryptoexception ce)
            {

            }
        }
        catch (ioexception ioeread)
        {
            ioeread.printstacktrace();
        }
    }

    /*
     * this method performs all the decryption and writes
     * the plain text to the buffered output stream created
     * previously.
     */
    private void performdecrypt(byte[] key)
    {    
        // initialise the cipher for decryption
        cipher.init(false, new keyparameter(key));

        /* 
         * as the decryption is from our preformatted file,
         * and we know that it's a hex encoded format, then
         * we wrap the inputstream with a bufferedreader
         * so that we can read it easily.
         */
        bufferedreader br = new bufferedreader(new inputstreamreader(in));

        /* 
         * now, read the file, and output the chunks
         */
        try
        {
            int outl;
            byte[] inblock = null;
            byte[] outblock = null;
            string rv = null;
            while ((rv = br.readline()) != null)
            {
                inblock = hex.decode(rv);
                outblock = new byte[cipher.getoutputsize(inblock.length)];

                outl = cipher.processbytes(inblock, 0, inblock.length, 
                                            outblock, 0);
                /*
                 * before we write anything out, we need to make sure
                 * that we've got something to write out. 
                 */
                if (outl > 0)
                {
                    out.write(outblock, 0, outl);
                }
            }

            try
            {
                /*
                 * now, process the bytes that are still buffered
                 * within the cipher.
                 */
                outl = cipher.dofinal(outblock, 0);
                if (outl > 0)
                {
                    out.write(outblock, 0, outl);
                }
            }
            catch (cryptoexception ce)
            {

            }
        }
        catch (ioexception ioeread)
        {
            ioeread.printstacktrace();
        }
    }

}

