package org.ripple.bouncycastle.openpgp.examples;

import java.io.fileoutputstream;
import java.io.ioexception;
import java.io.outputstream;
import java.math.biginteger;
import java.security.invalidkeyexception;
import java.security.keypair;
import java.security.keypairgenerator;
import java.security.nosuchproviderexception;
import java.security.security;
import java.security.signatureexception;
import java.util.date;

import org.ripple.bouncycastle.bcpg.armoredoutputstream;
import org.ripple.bouncycastle.bcpg.hashalgorithmtags;
import org.ripple.bouncycastle.jce.provider.bouncycastleprovider;
import org.ripple.bouncycastle.jce.spec.elgamalparameterspec;
import org.ripple.bouncycastle.openpgp.pgpencrypteddata;
import org.ripple.bouncycastle.openpgp.pgpexception;
import org.ripple.bouncycastle.openpgp.pgpkeypair;
import org.ripple.bouncycastle.openpgp.pgpkeyringgenerator;
import org.ripple.bouncycastle.openpgp.pgppublickey;
import org.ripple.bouncycastle.openpgp.pgpsignature;
import org.ripple.bouncycastle.openpgp.operator.pgpdigestcalculator;
import org.ripple.bouncycastle.openpgp.operator.jcajce.jcapgpcontentsignerbuilder;
import org.ripple.bouncycastle.openpgp.operator.jcajce.jcapgpdigestcalculatorproviderbuilder;
import org.ripple.bouncycastle.openpgp.operator.jcajce.jcapgpkeypair;
import org.ripple.bouncycastle.openpgp.operator.jcajce.jcepbesecretkeyencryptorbuilder;

/**
 * a simple utility class that generates a public/secret keyring containing a dsa signing
 * key and an el gamal key for encryption.
 * <p>
 * usage: dsaelgamalkeyringgenerator [-a] identity passphrase
 * <p>
 * where identity is the name to be associated with the public key. the keys are placed 
 * in the files pub.[asc|bpg] and secret.[asc|bpg].
 * <p>
 * <b>note</b>: this example encrypts the secret key using aes_256, many pgp products still
 * do not support this, if you are having problems importing keys try changing the algorithm
 * id to pgpencrypteddata.cast5. cast5 is more widely supported.
 */
public class dsaelgamalkeyringgenerator
{
    private static void exportkeypair(
        outputstream    secretout,
        outputstream    publicout,
        keypair         dsakp,
        keypair         elgkp,
        string          identity,
        char[]          passphrase,
        boolean         armor)
        throws ioexception, invalidkeyexception, nosuchproviderexception, signatureexception, pgpexception
    {
        if (armor)
        {
            secretout = new armoredoutputstream(secretout);
        }

        pgpkeypair        dsakeypair = new jcapgpkeypair(pgppublickey.dsa, dsakp, new date());
        pgpkeypair        elgkeypair = new jcapgpkeypair(pgppublickey.elgamal_encrypt, elgkp, new date());
        pgpdigestcalculator sha1calc = new jcapgpdigestcalculatorproviderbuilder().build().get(hashalgorithmtags.sha1);
        pgpkeyringgenerator    keyringgen = new pgpkeyringgenerator(pgpsignature.positive_certification, dsakeypair,
                 identity, sha1calc, null, null, new jcapgpcontentsignerbuilder(dsakeypair.getpublickey().getalgorithm(), hashalgorithmtags.sha1), new jcepbesecretkeyencryptorbuilder(pgpencrypteddata.aes_256, sha1calc).setprovider("bc").build(passphrase));
        
        keyringgen.addsubkey(elgkeypair);
        
        keyringgen.generatesecretkeyring().encode(secretout);
        
        secretout.close();
        
        if (armor)
        {
            publicout = new armoredoutputstream(publicout);
        }
        
        keyringgen.generatepublickeyring().encode(publicout);
        
        publicout.close();
    }
    
    public static void main(
        string[] args)
        throws exception
    {
        security.addprovider(new bouncycastleprovider());

        if (args.length < 2)
        {
            system.out.println("dsaelgamalkeyringgenerator [-a] identity passphrase");
            system.exit(0);
        }
        
        keypairgenerator    dsakpg = keypairgenerator.getinstance("dsa", "bc");
        
        dsakpg.initialize(1024);
        
        //
        // this takes a while as the key generator has to generate some dsa params
        // before it generates the key.
        //
        keypair             dsakp = dsakpg.generatekeypair();
        
        keypairgenerator    elgkpg = keypairgenerator.getinstance("elgamal", "bc");
        biginteger          g = new biginteger("153d5d6172adb43045b68ae8e1de1070b6137005686d29d3d73a7749199681ee5b212c9b96bfdcfa5b20cd5e3fd2044895d609cf9b410b7a0f12ca1cb9a428cc", 16);
        biginteger          p = new biginteger("9494fec095f3b85ee286542b3836fc81a5dd0a0349b4c239dd38744d488cf8e31db8bcb7d33b41abb9e5a33cca9144b1cef332c94bf0573bf047a3aca98cdf3b", 16);
            
        elgamalparameterspec         elparams = new elgamalparameterspec(p, g);
            
        elgkpg.initialize(elparams);
        
        //
        // this is quicker because we are using pregenerated parameters.
        //
        keypair                    elgkp = elgkpg.generatekeypair();
        
        if (args[0].equals("-a"))
        {
            if (args.length < 3)
            {
                system.out.println("dsaelgamalkeyringgenerator [-a] identity passphrase");
                system.exit(0);
            }
            
            fileoutputstream    out1 = new fileoutputstream("secret.asc");
            fileoutputstream    out2 = new fileoutputstream("pub.asc");
            
            exportkeypair(out1, out2, dsakp, elgkp, args[1], args[2].tochararray(), true);
        }
        else
        {
            fileoutputstream    out1 = new fileoutputstream("secret.bpg");
            fileoutputstream    out2 = new fileoutputstream("pub.bpg");
            
            exportkeypair(out1, out2, dsakp, elgkp, args[0], args[1].tochararray(), false);
        }
    }
}
