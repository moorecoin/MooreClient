package org.ripple.bouncycastle.openpgp.examples;

import java.io.bufferedinputstream;
import java.io.bufferedoutputstream;
import java.io.bytearrayoutputstream;
import java.io.fileinputstream;
import java.io.fileoutputstream;
import java.io.ioexception;
import java.io.inputstream;
import java.io.outputstream;
import java.security.nosuchalgorithmexception;
import java.security.nosuchproviderexception;
import java.security.security;
import java.security.signatureexception;
import java.util.iterator;

import org.ripple.bouncycastle.bcpg.armoredinputstream;
import org.ripple.bouncycastle.bcpg.armoredoutputstream;
import org.ripple.bouncycastle.bcpg.bcpgoutputstream;
import org.ripple.bouncycastle.jce.provider.bouncycastleprovider;
import org.ripple.bouncycastle.openpgp.pgpexception;
import org.ripple.bouncycastle.openpgp.pgpobjectfactory;
import org.ripple.bouncycastle.openpgp.pgpprivatekey;
import org.ripple.bouncycastle.openpgp.pgppublickey;
import org.ripple.bouncycastle.openpgp.pgppublickeyringcollection;
import org.ripple.bouncycastle.openpgp.pgpsecretkey;
import org.ripple.bouncycastle.openpgp.pgpsignature;
import org.ripple.bouncycastle.openpgp.pgpsignaturegenerator;
import org.ripple.bouncycastle.openpgp.pgpsignaturelist;
import org.ripple.bouncycastle.openpgp.pgpsignaturesubpacketgenerator;
import org.ripple.bouncycastle.openpgp.pgputil;
import org.ripple.bouncycastle.openpgp.operator.jcajce.jcapgpcontentsignerbuilder;
import org.ripple.bouncycastle.openpgp.operator.jcajce.jcapgpcontentverifierbuilderprovider;
import org.ripple.bouncycastle.openpgp.operator.jcajce.jcepbesecretkeydecryptorbuilder;

/**
 * a simple utility class that creates clear signed files and verifies them.
 * <p>
 * to sign a file: clearsignedfileprocessor -s filename secretkey passphrase.<br>
 * <p>
 * to decrypt: clearsignedfileprocessor -v filename signaturefile publickeyfile.
 */
public class clearsignedfileprocessor
{
    private static int readinputline(bytearrayoutputstream bout, inputstream fin)
        throws ioexception
    {
        bout.reset();

        int lookahead = -1;
        int ch;

        while ((ch = fin.read()) >= 0)
        {
            bout.write(ch);
            if (ch == '\r' || ch == '\n')
            {
                lookahead = readpassedeol(bout, ch, fin);
                break;
            }
        }

        return lookahead;
    }

    private static int readinputline(bytearrayoutputstream bout, int lookahead, inputstream fin)
        throws ioexception
    {
        bout.reset();

        int ch = lookahead;

        do
        {
            bout.write(ch);
            if (ch == '\r' || ch == '\n')
            {
                lookahead = readpassedeol(bout, ch, fin);
                break;
            }
        }
        while ((ch = fin.read()) >= 0);

        if (ch < 0)
        {
            lookahead = -1;
        }
        
        return lookahead;
    }

    private static int readpassedeol(bytearrayoutputstream bout, int lastch, inputstream fin)
        throws ioexception
    {
        int lookahead = fin.read();

        if (lastch == '\r' && lookahead == '\n')
        {
            bout.write(lookahead);
            lookahead = fin.read();
        }

        return lookahead;
    }

    /*
     * verify a clear text signed file
     */
    private static void verifyfile(
        inputstream        in,
        inputstream        keyin,
        string             resultname)
        throws exception
    {
        armoredinputstream    ain = new armoredinputstream(in);
        outputstream          out = new bufferedoutputstream(new fileoutputstream(resultname));



        //
        // write out signed section using the local line separator.
        // note: trailing white space needs to be removed from the end of
        // each line rfc 4880 section 7.1
        //
        bytearrayoutputstream lineout = new bytearrayoutputstream();
        int                   lookahead = readinputline(lineout, ain);
        byte[]                linesep = getlineseparator();

        if (lookahead != -1 && ain.iscleartext())
        {
            byte[] line = lineout.tobytearray();
            out.write(line, 0, getlengthwithoutseparatorortrailingwhitespace(line));
            out.write(linesep);

            while (lookahead != -1 && ain.iscleartext())
            {
                lookahead = readinputline(lineout, lookahead, ain);
                
                line = lineout.tobytearray();
                out.write(line, 0, getlengthwithoutseparatorortrailingwhitespace(line));
                out.write(linesep);
            }
        }

        out.close();

        pgppublickeyringcollection pgprings = new pgppublickeyringcollection(keyin);

        pgpobjectfactory           pgpfact = new pgpobjectfactory(ain);
        pgpsignaturelist           p3 = (pgpsignaturelist)pgpfact.nextobject();
        pgpsignature               sig = p3.get(0);

        pgppublickey publickey = pgprings.getpublickey(sig.getkeyid());
        sig.init(new jcapgpcontentverifierbuilderprovider().setprovider("bc"), publickey);

        //
        // read the input, making sure we ignore the last newline.
        //

        inputstream sigin = new bufferedinputstream(new fileinputstream(resultname));

        lookahead = readinputline(lineout, sigin);

        processline(sig, lineout.tobytearray());

        if (lookahead != -1)
        {
            do
            {
                lookahead = readinputline(lineout, lookahead, sigin);

                sig.update((byte)'\r');
                sig.update((byte)'\n');

                processline(sig, lineout.tobytearray());
            }
            while (lookahead != -1);
        }

        sigin.close();

        if (sig.verify())
        {
            system.out.println("signature verified.");
        }
        else
        {
            system.out.println("signature verification failed.");
        }
    }

    private static byte[] getlineseparator()
    {
        string nl = system.getproperty("line.separator");
        byte[] nlbytes = new byte[nl.length()];

        for (int i = 0; i != nlbytes.length; i++)
        {
            nlbytes[i] = (byte)nl.charat(i);
        }

        return nlbytes;
    }

    /*
     * create a clear text signed file.
     */
    private static void signfile(
        string          filename,
        inputstream     keyin,
        outputstream    out,
        char[]          pass,
        string          digestname)
        throws ioexception, nosuchalgorithmexception, nosuchproviderexception, pgpexception, signatureexception
    {    
        int digest;
        
        if (digestname.equals("sha256"))
        {
            digest = pgputil.sha256;
        }
        else if (digestname.equals("sha384"))
        {
            digest = pgputil.sha384;
        }
        else if (digestname.equals("sha512"))
        {
            digest = pgputil.sha512;
        }
        else if (digestname.equals("md5"))
        {
            digest = pgputil.md5;
        }
        else if (digestname.equals("ripemd160"))
        {
            digest = pgputil.ripemd160;
        }
        else
        {
            digest = pgputil.sha1;
        }
        
        pgpsecretkey                    pgpseckey = pgpexampleutil.readsecretkey(keyin);
        pgpprivatekey                   pgpprivkey = pgpseckey.extractprivatekey(new jcepbesecretkeydecryptorbuilder().setprovider("bc").build(pass));
        pgpsignaturegenerator           sgen = new pgpsignaturegenerator(new jcapgpcontentsignerbuilder(pgpseckey.getpublickey().getalgorithm(), digest).setprovider("bc"));
        pgpsignaturesubpacketgenerator  spgen = new pgpsignaturesubpacketgenerator();
        
        sgen.init(pgpsignature.canonical_text_document, pgpprivkey);
        
        iterator    it = pgpseckey.getpublickey().getuserids();
        if (it.hasnext())
        {
            spgen.setsigneruserid(false, (string)it.next());
            sgen.sethashedsubpackets(spgen.generate());
        }
        
        inputstream fin = new bufferedinputstream(new fileinputstream(filename));
        armoredoutputstream aout = new armoredoutputstream(out);
        
        aout.begincleartext(digest);

        //
        // note the last \n/\r/\r\n in the file is ignored
        //
        bytearrayoutputstream lineout = new bytearrayoutputstream();
        int lookahead = readinputline(lineout, fin);

        processline(aout, sgen, lineout.tobytearray());

        if (lookahead != -1)
        {
            do
            {
                lookahead = readinputline(lineout, lookahead, fin);

                sgen.update((byte)'\r');
                sgen.update((byte)'\n');

                processline(aout, sgen, lineout.tobytearray());
            }
            while (lookahead != -1);
        }

        fin.close();

        aout.endcleartext();
        
        bcpgoutputstream            bout = new bcpgoutputstream(aout);
        
        sgen.generate().encode(bout);

        aout.close();
    }

    private static void processline(pgpsignature sig, byte[] line)
        throws signatureexception, ioexception
    {
        int length = getlengthwithoutwhitespace(line);
        if (length > 0)
        {
            sig.update(line, 0, length);
        }
    }

    private static void processline(outputstream aout, pgpsignaturegenerator sgen, byte[] line)
        throws signatureexception, ioexception
    {
        // note: trailing white space needs to be removed from the end of
        // each line for signature calculation rfc 4880 section 7.1
        int length = getlengthwithoutwhitespace(line);
        if (length > 0)
        {
            sgen.update(line, 0, length);
        }

        aout.write(line, 0, line.length);
    }

    private static int getlengthwithoutseparatorortrailingwhitespace(byte[] line)
    {
        int    end = line.length - 1;

        while (end >= 0 && iswhitespace(line[end]))
        {
            end--;
        }

        return end + 1;
    }

    private static boolean islineending(byte b)
    {
        return b == '\r' || b == '\n';
    }

    private static int getlengthwithoutwhitespace(byte[] line)
    {
        int    end = line.length - 1;

        while (end >= 0 && iswhitespace(line[end]))
        {
            end--;
        }

        return end + 1;
    }

    private static boolean iswhitespace(byte b)
    {
        return islineending(b) || b == '\t' || b == ' ';
    }

    public static void main(
        string[] args)
        throws exception
    {
        security.addprovider(new bouncycastleprovider());

        if (args[0].equals("-s"))
        {
            inputstream        keyin = pgputil.getdecoderstream(new fileinputstream(args[2]));
            fileoutputstream   out = new fileoutputstream(args[1] + ".asc");
            
            if (args.length == 4)
            {
                signfile(args[1], keyin, out, args[3].tochararray(), "sha1");
            }
            else
            {
                signfile(args[1], keyin, out, args[3].tochararray(), args[4]);
            }
        }
        else if (args[0].equals("-v"))
        {
            if (args[1].indexof(".asc") < 0)
            {
                system.err.println("file needs to end in \".asc\"");
                system.exit(1);
            }
            fileinputstream    in = new fileinputstream(args[1]);
            inputstream        keyin = pgputil.getdecoderstream(new fileinputstream(args[2]));
                
            verifyfile(in, keyin, args[1].substring(0, args[1].length() - 4));
        }
        else
        {
            system.err.println("usage: clearsignedfileprocessor [-s file keyfile passphrase]|[-v sigfile keyfile]");
        }
    }
}
