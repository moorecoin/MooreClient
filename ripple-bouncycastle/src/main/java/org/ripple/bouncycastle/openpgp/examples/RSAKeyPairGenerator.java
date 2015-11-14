package org.ripple.bouncycastle.openpgp.examples;

import java.io.fileoutputstream;
import java.io.ioexception;
import java.io.outputstream;
import java.security.invalidkeyexception;
import java.security.keypair;
import java.security.keypairgenerator;
import java.security.nosuchproviderexception;
import java.security.privatekey;
import java.security.publickey;
import java.security.security;
import java.security.signatureexception;
import java.util.date;

import org.ripple.bouncycastle.bcpg.armoredoutputstream;
import org.ripple.bouncycastle.bcpg.hashalgorithmtags;
import org.ripple.bouncycastle.jce.provider.bouncycastleprovider;
import org.ripple.bouncycastle.openpgp.pgpencrypteddata;
import org.ripple.bouncycastle.openpgp.pgpexception;
import org.ripple.bouncycastle.openpgp.pgpkeypair;
import org.ripple.bouncycastle.openpgp.pgppublickey;
import org.ripple.bouncycastle.openpgp.pgpsecretkey;
import org.ripple.bouncycastle.openpgp.pgpsignature;
import org.ripple.bouncycastle.openpgp.operator.pgpdigestcalculator;
import org.ripple.bouncycastle.openpgp.operator.jcajce.jcapgpcontentsignerbuilder;
import org.ripple.bouncycastle.openpgp.operator.jcajce.jcapgpdigestcalculatorproviderbuilder;
import org.ripple.bouncycastle.openpgp.operator.jcajce.jcepbesecretkeyencryptorbuilder;

/**
 * a simple utility class that generates a rsa pgppublickey/pgpsecretkey pair.
 * <p>
 * usage: rsakeypairgenerator [-a] identity passphrase
 * <p>
 * where identity is the name to be associated with the public key. the keys are placed 
 * in the files pub.[asc|bpg] and secret.[asc|bpg].
 */
public class rsakeypairgenerator
{
    private static void exportkeypair(
        outputstream    secretout,
        outputstream    publicout,
        publickey       publickey,
        privatekey      privatekey,
        string          identity,
        char[]          passphrase,
        boolean         armor)
        throws ioexception, invalidkeyexception, nosuchproviderexception, signatureexception, pgpexception
    {    
        if (armor)
        {
            secretout = new armoredoutputstream(secretout);
        }

        pgpdigestcalculator sha1calc = new jcapgpdigestcalculatorproviderbuilder().build().get(hashalgorithmtags.sha1);
        pgpkeypair          keypair = new pgpkeypair(pgppublickey.rsa_general, publickey, privatekey, new date());
        pgpsecretkey        secretkey = new pgpsecretkey(pgpsignature.default_certification, keypair, identity, sha1calc, null, null, new jcapgpcontentsignerbuilder(keypair.getpublickey().getalgorithm(), hashalgorithmtags.sha1), new jcepbesecretkeyencryptorbuilder(pgpencrypteddata.cast5, sha1calc).setprovider("bc").build(passphrase));
        
        secretkey.encode(secretout);
        
        secretout.close();
        
        if (armor)
        {
            publicout = new armoredoutputstream(publicout);
        }

        pgppublickey    key = secretkey.getpublickey();
        
        key.encode(publicout);
        
        publicout.close();
    }
    
    public static void main(
        string[] args)
        throws exception
    {
        security.addprovider(new bouncycastleprovider());

        keypairgenerator    kpg = keypairgenerator.getinstance("rsa", "bc");
        
        kpg.initialize(1024);
        
        keypair                    kp = kpg.generatekeypair();
        
        if (args.length < 2)
        {
            system.out.println("rsakeypairgenerator [-a] identity passphrase");
            system.exit(0);
        }
        
        if (args[0].equals("-a"))
        {
            if (args.length < 3)
            {
                system.out.println("rsakeypairgenerator [-a] identity passphrase");
                system.exit(0);
            }
            
            fileoutputstream    out1 = new fileoutputstream("secret.asc");
            fileoutputstream    out2 = new fileoutputstream("pub.asc");
            
            exportkeypair(out1, out2, kp.getpublic(), kp.getprivate(), args[1], args[2].tochararray(), true);
        }
        else
        {
            fileoutputstream    out1 = new fileoutputstream("secret.bpg");
            fileoutputstream    out2 = new fileoutputstream("pub.bpg");
            
            exportkeypair(out1, out2, kp.getpublic(), kp.getprivate(), args[0], args[1].tochararray(), false);
        }
    }
}
