package org.ripple.bouncycastle.openpgp.examples;

import java.io.bufferedinputstream;
import java.io.bufferedoutputstream;
import java.io.fileinputstream;
import java.io.fileoutputstream;
import java.io.ioexception;
import java.io.inputstream;
import java.io.outputstream;
import java.security.generalsecurityexception;
import java.security.security;

import org.ripple.bouncycastle.bcpg.armoredoutputstream;
import org.ripple.bouncycastle.bcpg.bcpgoutputstream;
import org.ripple.bouncycastle.jce.provider.bouncycastleprovider;
import org.ripple.bouncycastle.openpgp.pgpcompresseddata;
import org.ripple.bouncycastle.openpgp.pgpexception;
import org.ripple.bouncycastle.openpgp.pgpobjectfactory;
import org.ripple.bouncycastle.openpgp.pgpprivatekey;
import org.ripple.bouncycastle.openpgp.pgppublickey;
import org.ripple.bouncycastle.openpgp.pgppublickeyringcollection;
import org.ripple.bouncycastle.openpgp.pgpsecretkey;
import org.ripple.bouncycastle.openpgp.pgpsignature;
import org.ripple.bouncycastle.openpgp.pgpsignaturegenerator;
import org.ripple.bouncycastle.openpgp.pgpsignaturelist;
import org.ripple.bouncycastle.openpgp.pgputil;
import org.ripple.bouncycastle.openpgp.operator.jcajce.jcapgpcontentsignerbuilder;
import org.ripple.bouncycastle.openpgp.operator.jcajce.jcapgpcontentverifierbuilderprovider;
import org.ripple.bouncycastle.openpgp.operator.jcajce.jcepbesecretkeydecryptorbuilder;

/**
 * a simple utility class that creates seperate signatures for files and verifies them.
 * <p>
 * to sign a file: detachedsignatureprocessor -s [-a] filename secretkey passphrase.<br>
 * if -a is specified the output file will be "ascii-armored".
 * <p>
 * to decrypt: detachedsignatureprocessor -v  filename signaturefile publickeyfile.
 * <p>
 * note: this example will silently overwrite files.
 * it also expects that a single pass phrase
 * will have been used.
 */
public class detachedsignatureprocessor
{
    private static void verifysignature(
        string filename,
        string inputfilename,
        string keyfilename)
        throws generalsecurityexception, ioexception, pgpexception
    {
        inputstream in = new bufferedinputstream(new fileinputstream(inputfilename));
        inputstream keyin = new bufferedinputstream(new fileinputstream(keyfilename));

        verifysignature(filename, in, keyin);

        keyin.close();
        in.close();
    }

    /*
     * verify the signature in in against the file filename.
     */
    private static void verifysignature(
        string          filename,
        inputstream     in,
        inputstream     keyin)
        throws generalsecurityexception, ioexception, pgpexception
    {
        in = pgputil.getdecoderstream(in);
        
        pgpobjectfactory    pgpfact = new pgpobjectfactory(in);
        pgpsignaturelist    p3;

        object    o = pgpfact.nextobject();
        if (o instanceof pgpcompresseddata)
        {
            pgpcompresseddata             c1 = (pgpcompresseddata)o;

            pgpfact = new pgpobjectfactory(c1.getdatastream());
            
            p3 = (pgpsignaturelist)pgpfact.nextobject();
        }
        else
        {
            p3 = (pgpsignaturelist)o;
        }
            
        pgppublickeyringcollection  pgppubringcollection = new pgppublickeyringcollection(pgputil.getdecoderstream(keyin));


        inputstream                 din = new bufferedinputstream(new fileinputstream(filename));

        pgpsignature                sig = p3.get(0);
        pgppublickey                key = pgppubringcollection.getpublickey(sig.getkeyid());

        sig.init(new jcapgpcontentverifierbuilderprovider().setprovider("bc"), key);

        int ch;
        while ((ch = din.read()) >= 0)
        {
            sig.update((byte)ch);
        }

        din.close();

        if (sig.verify())
        {
            system.out.println("signature verified.");
        }
        else
        {
            system.out.println("signature verification failed.");
        }
    }

    private static void createsignature(
        string  inputfilename,
        string  keyfilename,
        string  outputfilename,
        char[]  pass,
        boolean armor)
        throws generalsecurityexception, ioexception, pgpexception
    {
        inputstream keyin = new bufferedinputstream(new fileinputstream(keyfilename));
        outputstream out = new bufferedoutputstream(new fileoutputstream(outputfilename));

        createsignature(inputfilename, keyin, out, pass, armor);

        out.close();
        keyin.close();
    }

    private static void createsignature(
        string          filename,
        inputstream     keyin,
        outputstream    out,
        char[]          pass,
        boolean         armor)
        throws generalsecurityexception, ioexception, pgpexception
    {    
        if (armor)
        {
            out = new armoredoutputstream(out);
        }

        pgpsecretkey             pgpsec = pgpexampleutil.readsecretkey(keyin);
        pgpprivatekey            pgpprivkey = pgpsec.extractprivatekey(new jcepbesecretkeydecryptorbuilder().setprovider("bc").build(pass));
        pgpsignaturegenerator    sgen = new pgpsignaturegenerator(new jcapgpcontentsignerbuilder(pgpsec.getpublickey().getalgorithm(), pgputil.sha1).setprovider("bc"));
        
        sgen.init(pgpsignature.binary_document, pgpprivkey);
        
        bcpgoutputstream         bout = new bcpgoutputstream(out);
        
        inputstream              fin = new bufferedinputstream(new fileinputstream(filename));

        int ch;
        while ((ch = fin.read()) >= 0)
        {
            sgen.update((byte)ch);
        }

        fin.close();

        sgen.generate().encode(bout);

        if (armor)
        {
            out.close();
        }
    }

    public static void main(
        string[] args)
        throws exception
    {
        security.addprovider(new bouncycastleprovider());

        if (args[0].equals("-s"))
        {
            if (args[1].equals("-a"))
            {
                createsignature(args[2], args[3], args[2] + ".asc", args[4].tochararray(), true);
            }
            else
            {
                createsignature(args[1], args[2], args[1] + ".bpg", args[3].tochararray(), false);
            }
        }
        else if (args[0].equals("-v"))
        {
            verifysignature(args[1], args[2], args[3]);
        }
        else
        {
            system.err.println("usage: detachedsignatureprocessor [-s [-a] file keyfile passphrase]|[-v file sigfile keyfile]");
        }
    }
}
