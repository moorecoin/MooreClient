package org.ripple.bouncycastle.openpgp.examples;

import java.io.*;

import java.security.security;
import java.util.iterator;



import org.ripple.bouncycastle.bcpg.publickeyalgorithmtags;
import org.ripple.bouncycastle.jce.provider.bouncycastleprovider;
import org.ripple.bouncycastle.openpgp.pgppublickey;
import org.ripple.bouncycastle.openpgp.pgppublickeyring;
import org.ripple.bouncycastle.openpgp.pgppublickeyringcollection;
import org.ripple.bouncycastle.openpgp.pgputil;
import org.ripple.bouncycastle.util.encoders.hex;

/**
 * basic class which just lists the contents of the public key file passed
 * as an argument. if the file contains more than one "key ring" they are
 * listed in the order found.
 */
public class pubringdump 
{
    public static string getalgorithm(
        int    algid)
    {
        switch (algid)
        {
        case publickeyalgorithmtags.rsa_general:
            return "rsa_general";
        case publickeyalgorithmtags.rsa_encrypt:
            return "rsa_encrypt";
        case publickeyalgorithmtags.rsa_sign:
            return "rsa_sign";
        case publickeyalgorithmtags.elgamal_encrypt:
            return "elgamal_encrypt";
        case publickeyalgorithmtags.dsa:
            return "dsa";
        case publickeyalgorithmtags.ec:
            return "ec";
        case publickeyalgorithmtags.ecdsa:
            return "ecdsa";
        case publickeyalgorithmtags.elgamal_general:
            return "elgamal_general";
        case publickeyalgorithmtags.diffie_hellman:
            return "diffie_hellman";
        }

        return "unknown";
    }

    public static void main(string[] args)
        throws exception
    {
        security.addprovider(new bouncycastleprovider());
        
        pgputil.setdefaultprovider("bc");

        //
        // read the public key rings
        //
        pgppublickeyringcollection    pubrings = new pgppublickeyringcollection(
            pgputil.getdecoderstream(new fileinputstream(args[0])));

        iterator    rit = pubrings.getkeyrings();
            
        while (rit.hasnext())
        {
            pgppublickeyring    pgppub = (pgppublickeyring)rit.next();

            try
            {
                pgppub.getpublickey();
            }
            catch (exception e)
            {
                e.printstacktrace();
                continue;
            }

            iterator    it = pgppub.getpublickeys();
            boolean     first = true;
            while (it.hasnext())
            {
                pgppublickey    pgpkey = (pgppublickey)it.next();

                if (first)
                {
                    system.out.println("key id: " + long.tohexstring(pgpkey.getkeyid()));
                    first = false;
                }
                else
                {
                    system.out.println("key id: " + long.tohexstring(pgpkey.getkeyid()) + " (subkey)");
                }
                system.out.println("            algorithm: " + getalgorithm(pgpkey.getalgorithm()));
                system.out.println("            fingerprint: " + new string(hex.encode(pgpkey.getfingerprint())));
            }
        }
    }
}
