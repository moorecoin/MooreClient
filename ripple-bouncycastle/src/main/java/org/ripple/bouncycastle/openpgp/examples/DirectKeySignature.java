package org.ripple.bouncycastle.openpgp.examples;

import java.io.bytearrayinputstream;
import java.io.bytearrayoutputstream;
import java.io.fileinputstream;
import java.io.fileoutputstream;
import java.io.outputstream;
import java.security.security;
import java.util.iterator;

import org.ripple.bouncycastle.bcpg.armoredoutputstream;
import org.ripple.bouncycastle.bcpg.bcpgoutputstream;
import org.ripple.bouncycastle.bcpg.sig.notationdata;
import org.ripple.bouncycastle.jce.provider.bouncycastleprovider;
import org.ripple.bouncycastle.openpgp.pgpprivatekey;
import org.ripple.bouncycastle.openpgp.pgppublickey;
import org.ripple.bouncycastle.openpgp.pgppublickeyring;
import org.ripple.bouncycastle.openpgp.pgpsecretkey;
import org.ripple.bouncycastle.openpgp.pgpsecretkeyring;
import org.ripple.bouncycastle.openpgp.pgpsignature;
import org.ripple.bouncycastle.openpgp.pgpsignaturegenerator;
import org.ripple.bouncycastle.openpgp.pgpsignaturesubpacketgenerator;
import org.ripple.bouncycastle.openpgp.pgpsignaturesubpacketvector;
import org.ripple.bouncycastle.openpgp.pgputil;
import org.ripple.bouncycastle.openpgp.operator.jcajce.jcakeyfingerprintcalculator;
import org.ripple.bouncycastle.openpgp.operator.jcajce.jcapgpcontentsignerbuilder;
import org.ripple.bouncycastle.openpgp.operator.jcajce.jcepbesecretkeydecryptorbuilder;

/**
 * a simple utility class that directly signs a public key and writes the signed key to "signedkey.asc" in 
 * the current working directory.
 * <p>
 * to sign a key: directkeysignature secretkeyfile secretkeypass publickeyfile(key to be signed) notationname notationvalue.<br/>
 * </p><p>
 * to display a notationdata packet from a publickey previously signed: directkeysignature signedpublickeyfile.<br/>
 * </p><p>
 * <b>note</b>: this example will silently overwrite files, nor does it pay any attention to
 * the specification of "_console" in the filename. it also expects that a single pass phrase
 * will have been used.
 * </p>
 */
public class directkeysignature
{
    public static void main(
        string[] args)
    throws exception
    {
        security.addprovider(new bouncycastleprovider());

        if (args.length == 1)
        {
            pgppublickeyring ring = new pgppublickeyring(pgputil.getdecoderstream(new fileinputstream(args[0])), new jcakeyfingerprintcalculator());
            pgppublickey key = ring.getpublickey();
            
            // iterate through all direct key signautures and look for notationdata subpackets
            iterator iter = key.getsignaturesoftype(pgpsignature.direct_key);
            while(iter.hasnext())
            {
                pgpsignature    sig = (pgpsignature)iter.next();
                
                system.out.println("signature date is: " + sig.gethashedsubpackets().getsignaturecreationtime());

                notationdata[] data = sig.gethashedsubpackets().getnotationdataoccurences();//.getsubpacket(signaturesubpackettags.notation_data);
                
                for (int i = 0; i < data.length; i++)
                {
                    system.out.println("found notaion named '"+data[i].getnotationname()+"' with content '"+data[i].getnotationvalue()+"'.");
                }
            }
        }
        else if (args.length == 5)
        {
            // gather command line arguments
            pgpsecretkeyring secring = new pgpsecretkeyring(pgputil.getdecoderstream(new fileinputstream(args[0])), new jcakeyfingerprintcalculator());
            string secretkeypass = args[1];
            pgppublickeyring ring = new pgppublickeyring(pgputil.getdecoderstream(new fileinputstream(args[2])), new jcakeyfingerprintcalculator());
            string notationname = args[3];
            string notationvalue = args[4];

            // create the signed keyring
            pgppublickeyring sring = new pgppublickeyring(new bytearrayinputstream(signpublickey(secring.getsecretkey(), secretkeypass, ring.getpublickey(), notationname, notationvalue, true)), new jcakeyfingerprintcalculator());
            ring = sring;

            // write the created keyring to file
            armoredoutputstream out = new armoredoutputstream(new fileoutputstream("signedkey.asc"));
            sring.encode(out);
            out.flush();
            out.close();
        }
        else
        {
            system.err.println("usage: directkeysignature secretkeyfile secretkeypass publickeyfile(key to be signed) notationname notationvalue");
            system.err.println("or: directkeysignature signedpublickeyfile");

        }
    }

    private static byte[] signpublickey(pgpsecretkey secretkey, string secretkeypass, pgppublickey keytobesigned, string notationname, string notationvalue, boolean armor) throws exception
    {
        outputstream out = new bytearrayoutputstream();

        if (armor)
        {
            out = new armoredoutputstream(out);
        }

        pgpprivatekey pgpprivkey = secretkey.extractprivatekey(new jcepbesecretkeydecryptorbuilder().setprovider("bc").build(secretkeypass.tochararray()));

        pgpsignaturegenerator       sgen = new pgpsignaturegenerator(new jcapgpcontentsignerbuilder(secretkey.getpublickey().getalgorithm(), pgputil.sha1).setprovider("bc"));

        sgen.init(pgpsignature.direct_key, pgpprivkey);

        bcpgoutputstream            bout = new bcpgoutputstream(out);

        sgen.generateonepassversion(false).encode(bout);

        pgpsignaturesubpacketgenerator spgen = new pgpsignaturesubpacketgenerator();

        boolean ishumanreadable = true;

        spgen.setnotationdata(true, ishumanreadable, notationname, notationvalue);

        pgpsignaturesubpacketvector packetvector = spgen.generate();
        sgen.sethashedsubpackets(packetvector);

        bout.flush();

        if (armor)
        {
            out.close();
        }

        return pgppublickey.addcertification(keytobesigned, sgen.generate()).getencoded();
    }
}
