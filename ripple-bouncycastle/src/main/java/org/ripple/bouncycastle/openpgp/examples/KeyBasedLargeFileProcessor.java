package org.ripple.bouncycastle.openpgp.examples;

import java.io.bufferedinputstream;
import java.io.bufferedoutputstream;
import java.io.file;
import java.io.fileinputstream;
import java.io.fileoutputstream;
import java.io.ioexception;
import java.io.inputstream;
import java.io.outputstream;
import java.security.nosuchproviderexception;
import java.security.securerandom;
import java.security.security;
import java.util.iterator;

import org.ripple.bouncycastle.bcpg.armoredoutputstream;
import org.ripple.bouncycastle.jce.provider.bouncycastleprovider;
import org.ripple.bouncycastle.openpgp.pgpcompresseddata;
import org.ripple.bouncycastle.openpgp.pgpcompresseddatagenerator;
import org.ripple.bouncycastle.openpgp.pgpencrypteddata;
import org.ripple.bouncycastle.openpgp.pgpencrypteddatagenerator;
import org.ripple.bouncycastle.openpgp.pgpencrypteddatalist;
import org.ripple.bouncycastle.openpgp.pgpexception;
import org.ripple.bouncycastle.openpgp.pgpliteraldata;
import org.ripple.bouncycastle.openpgp.pgpobjectfactory;
import org.ripple.bouncycastle.openpgp.pgponepasssignaturelist;
import org.ripple.bouncycastle.openpgp.pgpprivatekey;
import org.ripple.bouncycastle.openpgp.pgppublickey;
import org.ripple.bouncycastle.openpgp.pgppublickeyencrypteddata;
import org.ripple.bouncycastle.openpgp.pgpsecretkeyringcollection;
import org.ripple.bouncycastle.openpgp.pgputil;
import org.ripple.bouncycastle.openpgp.operator.jcajce.jcepgpdataencryptorbuilder;
import org.ripple.bouncycastle.openpgp.operator.jcajce.jcepublickeydatadecryptorfactorybuilder;
import org.ripple.bouncycastle.openpgp.operator.jcajce.jcepublickeykeyencryptionmethodgenerator;
import org.ripple.bouncycastle.util.io.streams;

/**
 * a simple utility class that encrypts/decrypts public key based
 * encryption large files.
 * <p>
 * to encrypt a file: keybasedlargefileprocessor -e [-a|-ai] filename publickeyfile.<br>
 * if -a is specified the output file will be "ascii-armored".
 * if -i is specified the output file will be have integrity checking added.
 * <p>
 * to decrypt: keybasedlargefileprocessor -d filename secretkeyfile passphrase.
 * <p>
 * note 1: this example will silently overwrite files, nor does it pay any attention to
 * the specification of "_console" in the filename. it also expects that a single pass phrase
 * will have been used.
 * <p>
 * note 2: this example generates partial packets to encode the file, the output it generates
 * will not be readable by older pgp products or products that don't support partial packet 
 * encoding.
 * <p>
 * note 3: if an empty file name has been specified in the literal data object contained in the
 * encrypted packet a file with the name filename.out will be generated in the current working directory.
 */
public class keybasedlargefileprocessor
{
    private static void decryptfile(
        string inputfilename,
        string keyfilename,
        char[] passwd,
        string defaultfilename)
        throws ioexception, nosuchproviderexception
    {
        inputstream in = new bufferedinputstream(new fileinputstream(inputfilename));
        inputstream keyin = new bufferedinputstream(new fileinputstream(keyfilename));
        decryptfile(in, keyin, passwd, defaultfilename);
        keyin.close();
        in.close();
    }
    
    /**
     * decrypt the passed in message stream
     */
    private static void decryptfile(
        inputstream in,
        inputstream keyin,
        char[]      passwd,
        string      defaultfilename)
        throws ioexception, nosuchproviderexception
    {    
        in = pgputil.getdecoderstream(in);
        
        try
        {
            pgpobjectfactory        pgpf = new pgpobjectfactory(in);
            pgpencrypteddatalist    enc;

            object                  o = pgpf.nextobject();
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
            
            //
            // find the secret key
            //
            iterator                    it = enc.getencrypteddataobjects();
            pgpprivatekey               skey = null;
            pgppublickeyencrypteddata   pbe = null;
            pgpsecretkeyringcollection  pgpsec = new pgpsecretkeyringcollection(
                pgputil.getdecoderstream(keyin));                                                                 
            
            while (skey == null && it.hasnext())
            {
                pbe = (pgppublickeyencrypteddata)it.next();
                
                skey = pgpexampleutil.findsecretkey(pgpsec, pbe.getkeyid(), passwd);
            }
            
            if (skey == null)
            {
                throw new illegalargumentexception("secret key for message not found.");
            }
            
            inputstream         clear = pbe.getdatastream(new jcepublickeydatadecryptorfactorybuilder().setprovider("bc").build(skey));
            
            pgpobjectfactory    plainfact = new pgpobjectfactory(clear);
            
            pgpcompresseddata   cdata = (pgpcompresseddata)plainfact.nextobject();
    
            inputstream         compressedstream = new bufferedinputstream(cdata.getdatastream());
            pgpobjectfactory    pgpfact = new pgpobjectfactory(compressedstream);
            
            object              message = pgpfact.nextobject();
            
            if (message instanceof pgpliteraldata)
            {
                pgpliteraldata ld = (pgpliteraldata)message;

                string outfilename = ld.getfilename();
                if (outfilename.length() == 0)
                {
                    outfilename = defaultfilename;
                }

                inputstream unc = ld.getinputstream();
                outputstream fout =  new bufferedoutputstream(new fileoutputstream(outfilename));

                streams.pipeall(unc, fout);

                fout.close();
            }
            else if (message instanceof pgponepasssignaturelist)
            {
                throw new pgpexception("encrypted message contains a signed message - not literal data.");
            }
            else
            {
                throw new pgpexception("message is not a simple encrypted file - type unknown.");
            }

            if (pbe.isintegrityprotected())
            {
                if (!pbe.verify())
                {
                    system.err.println("message failed integrity check");
                }
                else
                {
                    system.err.println("message integrity check passed");
                }
            }
            else
            {
                system.err.println("no message integrity check");
            }
        }
        catch (pgpexception e)
        {
            system.err.println(e);
            if (e.getunderlyingexception() != null)
            {
                e.getunderlyingexception().printstacktrace();
            }
        }
    }

    private static void encryptfile(
        string          outputfilename,
        string          inputfilename,
        string          enckeyfilename,
        boolean         armor,
        boolean         withintegritycheck)
        throws ioexception, nosuchproviderexception, pgpexception
    {
        outputstream out = new bufferedoutputstream(new fileoutputstream(outputfilename));
        pgppublickey enckey = pgpexampleutil.readpublickey(enckeyfilename);
        encryptfile(out, inputfilename, enckey, armor, withintegritycheck);
        out.close();
    }

    private static void encryptfile(
        outputstream    out,
        string          filename,
        pgppublickey    enckey,
        boolean         armor,
        boolean         withintegritycheck)
        throws ioexception, nosuchproviderexception
    {    
        if (armor)
        {
            out = new armoredoutputstream(out);
        }
        
        try
        {    
            pgpencrypteddatagenerator   cpk = new pgpencrypteddatagenerator(new jcepgpdataencryptorbuilder(pgpencrypteddata.cast5).setwithintegritypacket(withintegritycheck).setsecurerandom(new securerandom()).setprovider("bc"));
                
            cpk.addmethod(new jcepublickeykeyencryptionmethodgenerator(enckey).setprovider("bc"));
            
            outputstream                cout = cpk.open(out, new byte[1 << 16]);
            
            pgpcompresseddatagenerator  comdata = new pgpcompresseddatagenerator(
                                                                    pgpcompresseddata.zip);
                                                                    
            pgputil.writefiletoliteraldata(comdata.open(cout), pgpliteraldata.binary, new file(filename), new byte[1 << 16]);
            
            comdata.close();
            
            cout.close();

            if (armor)
            {
                out.close();
            }
        }
        catch (pgpexception e)
        {
            system.err.println(e);
            if (e.getunderlyingexception() != null)
            {
                e.getunderlyingexception().printstacktrace();
            }
        }
    }

    public static void main(
        string[] args)
        throws exception
    {
        security.addprovider(new bouncycastleprovider());

        if (args.length == 0)
        {
            system.err.println("usage: keybasedlargefileprocessor -e|-d [-a|ai] file [secretkeyfile passphrase|pubkeyfile]");
            return;
        }
        
        if (args[0].equals("-e"))
        {
            if (args[1].equals("-a") || args[1].equals("-ai") || args[1].equals("-ia"))
            {
                encryptfile(args[2] + ".asc", args[2], args[3], true, (args[1].indexof('i') > 0));
            }
            else if (args[1].equals("-i"))
            {
                encryptfile(args[2] + ".bpg", args[2], args[3], false, true);
            }
            else
            {
                encryptfile(args[1] + ".bpg", args[1], args[2], false, false);
            }
        }
        else if (args[0].equals("-d"))
        {
            decryptfile(args[1], args[2], args[3].tochararray(), new file(args[1]).getname() + ".out");
        }
        else
        {
            system.err.println("usage: keybasedlargefileprocessor -d|-e [-a|ai] file [secretkeyfile passphrase|pubkeyfile]");
        }
    }
}
