package org.ripple.bouncycastle.openpgp.examples;

import java.io.file;
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

import org.ripple.bouncycastle.bcpg.armoredoutputstream;
import org.ripple.bouncycastle.bcpg.bcpgoutputstream;
import org.ripple.bouncycastle.jce.provider.bouncycastleprovider;
import org.ripple.bouncycastle.openpgp.pgpcompresseddata;
import org.ripple.bouncycastle.openpgp.pgpcompresseddatagenerator;
import org.ripple.bouncycastle.openpgp.pgpexception;
import org.ripple.bouncycastle.openpgp.pgpliteraldata;
import org.ripple.bouncycastle.openpgp.pgpliteraldatagenerator;
import org.ripple.bouncycastle.openpgp.pgpobjectfactory;
import org.ripple.bouncycastle.openpgp.pgponepasssignature;
import org.ripple.bouncycastle.openpgp.pgponepasssignaturelist;
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
 * a simple utility class that signs and verifies files.
 * <p>
 * to sign a file: signedfileprocessor -s [-a] filename secretkey passphrase.<br>
 * if -a is specified the output file will be "ascii-armored".
 * <p>
 * to decrypt: signedfileprocessor -v filename publickeyfile.
 * <p>
 * <b>note</b>: this example will silently overwrite files, nor does it pay any attention to
 * the specification of "_console" in the filename. it also expects that a single pass phrase
 * will have been used.
 * <p>
 * <b>note</b>: the example also makes use of pgp compression. if you are having difficulty getting it
 * to interoperate with other pgp programs try removing the use of compression first.
 */
public class signedfileprocessor
{
    /*
     * verify the passed in file as being correctly signed.
     */
    private static void verifyfile(
        inputstream        in,
        inputstream        keyin)
        throws exception
    {
        in = pgputil.getdecoderstream(in);
        
        pgpobjectfactory            pgpfact = new pgpobjectfactory(in);

        pgpcompresseddata           c1 = (pgpcompresseddata)pgpfact.nextobject();

        pgpfact = new pgpobjectfactory(c1.getdatastream());
            
        pgponepasssignaturelist     p1 = (pgponepasssignaturelist)pgpfact.nextobject();
            
        pgponepasssignature         ops = p1.get(0);
            
        pgpliteraldata              p2 = (pgpliteraldata)pgpfact.nextobject();

        inputstream                 din = p2.getinputstream();
        int                         ch;
        pgppublickeyringcollection  pgpring = new pgppublickeyringcollection(pgputil.getdecoderstream(keyin));

        pgppublickey                key = pgpring.getpublickey(ops.getkeyid());
        fileoutputstream            out = new fileoutputstream(p2.getfilename());

        ops.init(new jcapgpcontentverifierbuilderprovider().setprovider("bc"), key);
            
        while ((ch = din.read()) >= 0)
        {
            ops.update((byte)ch);
            out.write(ch);
        }

        out.close();
        
        pgpsignaturelist            p3 = (pgpsignaturelist)pgpfact.nextobject();

        if (ops.verify(p3.get(0)))
        {
            system.out.println("signature verified.");
        }
        else
        {
            system.out.println("signature verification failed.");
        }
    }

    /**
     * generate an encapsulated signed file.
     * 
     * @param filename
     * @param keyin
     * @param out
     * @param pass
     * @param armor
     * @throws ioexception
     * @throws nosuchalgorithmexception
     * @throws nosuchproviderexception
     * @throws pgpexception
     * @throws signatureexception
     */
    private static void signfile(
        string          filename,
        inputstream     keyin,
        outputstream    out,
        char[]          pass,
        boolean         armor)
        throws ioexception, nosuchalgorithmexception, nosuchproviderexception, pgpexception, signatureexception
    {
        if (armor)
        {
            out = new armoredoutputstream(out);
        }

        pgpsecretkey                pgpsec = pgpexampleutil.readsecretkey(keyin);
        pgpprivatekey               pgpprivkey = pgpsec.extractprivatekey(new jcepbesecretkeydecryptorbuilder().setprovider("bc").build(pass));
        pgpsignaturegenerator       sgen = new pgpsignaturegenerator(new jcapgpcontentsignerbuilder(pgpsec.getpublickey().getalgorithm(), pgputil.sha1).setprovider("bc"));
        
        sgen.init(pgpsignature.binary_document, pgpprivkey);
        
        iterator    it = pgpsec.getpublickey().getuserids();
        if (it.hasnext())
        {
            pgpsignaturesubpacketgenerator  spgen = new pgpsignaturesubpacketgenerator();
            
            spgen.setsigneruserid(false, (string)it.next());
            sgen.sethashedsubpackets(spgen.generate());
        }
        
        pgpcompresseddatagenerator  cgen = new pgpcompresseddatagenerator(
                                                                pgpcompresseddata.zlib);
        
        bcpgoutputstream            bout = new bcpgoutputstream(cgen.open(out));
        
        sgen.generateonepassversion(false).encode(bout);
        
        file                        file = new file(filename);
        pgpliteraldatagenerator     lgen = new pgpliteraldatagenerator();
        outputstream                lout = lgen.open(bout, pgpliteraldata.binary, file);
        fileinputstream             fin = new fileinputstream(file);
        int                         ch;
        
        while ((ch = fin.read()) >= 0)
        {
            lout.write(ch);
            sgen.update((byte)ch);
        }

        lgen.close();

        sgen.generate().encode(bout);

        cgen.close();

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
                fileinputstream     keyin = new fileinputstream(args[3]);
                fileoutputstream    out = new fileoutputstream(args[2] + ".asc");
                
                signfile(args[2], keyin, out, args[4].tochararray(), true);
            }
            else
            {
                fileinputstream     keyin = new fileinputstream(args[2]);
                fileoutputstream    out = new fileoutputstream(args[1] + ".bpg");
                
                signfile(args[1], keyin, out, args[3].tochararray(), false);
            }
        }
        else if (args[0].equals("-v"))
        {
            fileinputstream    in = new fileinputstream(args[1]);
            fileinputstream    keyin = new fileinputstream(args[2]);
            
            verifyfile(in, keyin);
        }
        else
        {
            system.err.println("usage: signedfileprocessor -v|-s [-a] file keyfile [passphrase]");
        }
    }
}