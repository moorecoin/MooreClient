package org.ripple.bouncycastle.jce.examples;

import java.io.fileoutputstream;
import java.math.biginteger;
import java.security.keyfactory;
import java.security.keystore;
import java.security.privatekey;
import java.security.publickey;
import java.security.security;
import java.security.cert.certificate;
import java.security.cert.x509certificate;
import java.security.spec.rsaprivatecrtkeyspec;
import java.security.spec.rsapublickeyspec;
import java.util.date;
import java.util.hashtable;
import java.util.vector;

import org.ripple.bouncycastle.asn1.derbmpstring;
import org.ripple.bouncycastle.asn1.pkcs.pkcsobjectidentifiers;
import org.ripple.bouncycastle.asn1.x509.basicconstraints;
import org.ripple.bouncycastle.asn1.x509.x509extensions;
import org.ripple.bouncycastle.jce.principalutil;
import org.ripple.bouncycastle.jce.x509principal;
import org.ripple.bouncycastle.jce.interfaces.pkcs12bagattributecarrier;
import org.ripple.bouncycastle.jce.provider.bouncycastleprovider;
import org.ripple.bouncycastle.x509.x509v1certificategenerator;
import org.ripple.bouncycastle.x509.x509v3certificategenerator;
import org.ripple.bouncycastle.x509.extension.authoritykeyidentifierstructure;
import org.ripple.bouncycastle.x509.extension.subjectkeyidentifierstructure;

/**
 * example of how to set up a certificiate chain and a pkcs 12 store for
 * a private individual - obviously you'll need to generate your own keys,
 * and you may need to add a netscapecerttype extension or add a key
 * usage extension depending on your application, but you should get the
 * idea! as always this is just an example...
 */
public class pkcs12example
{
    static char[]   passwd = { 'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd' };
    
    static x509v1certificategenerator  v1certgen = new x509v1certificategenerator();
    static x509v3certificategenerator  v3certgen = new x509v3certificategenerator();

    /**
     * we generate the ca's certificate
     */
    public static certificate createmastercert(
        publickey       pubkey,
        privatekey      privkey)
        throws exception
    {
        //
        // signers name 
        //
        string  issuer = "c=au, o=the legion of the bouncy castle, ou=bouncy primary certificate";

        //
        // subjects name - the same as we are self signed.
        //
        string  subject = "c=au, o=the legion of the bouncy castle, ou=bouncy primary certificate";

        //
        // create the certificate - version 1
        //

        v1certgen.setserialnumber(biginteger.valueof(1));
        v1certgen.setissuerdn(new x509principal(issuer));
        v1certgen.setnotbefore(new date(system.currenttimemillis() - 1000l * 60 * 60 * 24 * 30));
        v1certgen.setnotafter(new date(system.currenttimemillis() + (1000l * 60 * 60 * 24 * 30)));
        v1certgen.setsubjectdn(new x509principal(subject));
        v1certgen.setpublickey(pubkey);
        v1certgen.setsignaturealgorithm("sha1withrsaencryption");

        x509certificate cert = v1certgen.generate(privkey);

        cert.checkvalidity(new date());

        cert.verify(pubkey);

        pkcs12bagattributecarrier   bagattr = (pkcs12bagattributecarrier)cert;

        //
        // this is actually optional - but if you want to have control
        // over setting the friendly name this is the way to do it...
        //
        bagattr.setbagattribute(
            pkcsobjectidentifiers.pkcs_9_at_friendlyname,
            new derbmpstring("bouncy primary certificate"));

        return cert;
    }

    /**
     * we generate an intermediate certificate signed by our ca
     */
    public static certificate createintermediatecert(
        publickey       pubkey,
        privatekey      caprivkey,
        x509certificate cacert)
        throws exception
    {
        //
        // subject name table.
        //
        hashtable                   attrs = new hashtable();
        vector                      order = new vector();

        attrs.put(x509principal.c, "au");
        attrs.put(x509principal.o, "the legion of the bouncy castle");
        attrs.put(x509principal.ou, "bouncy intermediate certificate");
        attrs.put(x509principal.emailaddress, "feedback-crypto@bouncycastle.org");

        order.addelement(x509principal.c);
        order.addelement(x509principal.o);
        order.addelement(x509principal.ou);
        order.addelement(x509principal.emailaddress);

        //
        // create the certificate - version 3
        //
        v3certgen.reset();

        v3certgen.setserialnumber(biginteger.valueof(2));
        v3certgen.setissuerdn(principalutil.getsubjectx509principal(cacert));
        v3certgen.setnotbefore(new date(system.currenttimemillis() - 1000l * 60 * 60 * 24 * 30));
        v3certgen.setnotafter(new date(system.currenttimemillis() + (1000l * 60 * 60 * 24 * 30)));
        v3certgen.setsubjectdn(new x509principal(order, attrs));
        v3certgen.setpublickey(pubkey);
        v3certgen.setsignaturealgorithm("sha1withrsaencryption");

        //
        // extensions
        //
        v3certgen.addextension(
            x509extensions.subjectkeyidentifier,
            false,
            new subjectkeyidentifierstructure(pubkey));

        v3certgen.addextension(
            x509extensions.authoritykeyidentifier,
            false,
            new authoritykeyidentifierstructure(cacert));

        v3certgen.addextension(
            x509extensions.basicconstraints,
            true,
            new basicconstraints(0));

        x509certificate cert = v3certgen.generate(caprivkey);

        cert.checkvalidity(new date());

        cert.verify(cacert.getpublickey());

        pkcs12bagattributecarrier   bagattr = (pkcs12bagattributecarrier)cert;

        //
        // this is actually optional - but if you want to have control
        // over setting the friendly name this is the way to do it...
        //
        bagattr.setbagattribute(
            pkcsobjectidentifiers.pkcs_9_at_friendlyname,
            new derbmpstring("bouncy intermediate certificate"));

        return cert;
    }

    /**
     * we generate a certificate signed by our ca's intermediate certficate
     */
    public static certificate createcert(
        publickey       pubkey,
        privatekey      caprivkey,
        publickey       capubkey)
        throws exception
    {
        //
        // signers name table.
        //
        hashtable                   sattrs = new hashtable();
        vector                      sorder = new vector();

        sattrs.put(x509principal.c, "au");
        sattrs.put(x509principal.o, "the legion of the bouncy castle");
        sattrs.put(x509principal.ou, "bouncy intermediate certificate");
        sattrs.put(x509principal.emailaddress, "feedback-crypto@bouncycastle.org");

        sorder.addelement(x509principal.c);
        sorder.addelement(x509principal.o);
        sorder.addelement(x509principal.ou);
        sorder.addelement(x509principal.emailaddress);

        //
        // subjects name table.
        //
        hashtable                   attrs = new hashtable();
        vector                      order = new vector();

        attrs.put(x509principal.c, "au");
        attrs.put(x509principal.o, "the legion of the bouncy castle");
        attrs.put(x509principal.l, "melbourne");
        attrs.put(x509principal.cn, "eric h. echidna");
        attrs.put(x509principal.emailaddress, "feedback-crypto@bouncycastle.org");

        order.addelement(x509principal.c);
        order.addelement(x509principal.o);
        order.addelement(x509principal.l);
        order.addelement(x509principal.cn);
        order.addelement(x509principal.emailaddress);

        //
        // create the certificate - version 3
        //
        v3certgen.reset();

        v3certgen.setserialnumber(biginteger.valueof(3));
        v3certgen.setissuerdn(new x509principal(sorder, sattrs));
        v3certgen.setnotbefore(new date(system.currenttimemillis() - 1000l * 60 * 60 * 24 * 30));
        v3certgen.setnotafter(new date(system.currenttimemillis() + (1000l * 60 * 60 * 24 * 30)));
        v3certgen.setsubjectdn(new x509principal(order, attrs));
        v3certgen.setpublickey(pubkey);
        v3certgen.setsignaturealgorithm("sha1withrsaencryption");

        //
        // add the extensions
        //
        v3certgen.addextension(
            x509extensions.subjectkeyidentifier,
            false,
            new subjectkeyidentifierstructure(pubkey));

        v3certgen.addextension(
            x509extensions.authoritykeyidentifier,
            false,
            new authoritykeyidentifierstructure(capubkey));

        x509certificate cert = v3certgen.generate(caprivkey);

        cert.checkvalidity(new date());

        cert.verify(capubkey);

        pkcs12bagattributecarrier   bagattr = (pkcs12bagattributecarrier)cert;

        //
        // this is also optional - in the sense that if you leave this
        // out the keystore will add it automatically, note though that
        // for the browser to recognise the associated private key this
        // you should at least use the pkcs_9_localkeyid oid and set it
        // to the same as you do for the private key's localkeyid.
        //
        bagattr.setbagattribute(
            pkcsobjectidentifiers.pkcs_9_at_friendlyname,
            new derbmpstring("eric's key"));
        bagattr.setbagattribute(
            pkcsobjectidentifiers.pkcs_9_at_localkeyid,
            new subjectkeyidentifierstructure(pubkey));

        return cert;
    }

    public static void main(
        string[]    args)
        throws exception
    {
        security.addprovider(new bouncycastleprovider());

        //
        // personal keys
        //
        rsapublickeyspec pubkeyspec = new rsapublickeyspec(
            new biginteger("b4a7e46170574f16a97082b22be58b6a2a629798419be12872a4bdba626cfae9900f76abfb12139dce5de56564fab2b6543165a040c606887420e33d91ed7ed7", 16),
            new biginteger("11", 16));

        rsaprivatecrtkeyspec privkeyspec = new rsaprivatecrtkeyspec(
            new biginteger("b4a7e46170574f16a97082b22be58b6a2a629798419be12872a4bdba626cfae9900f76abfb12139dce5de56564fab2b6543165a040c606887420e33d91ed7ed7", 16),
            new biginteger("11", 16),
            new biginteger("9f66f6b05410cd503b2709e88115d55daced94d1a34d4e32bf824d0dde6028ae79c5f07b580f5dce240d7111f7ddb130a7945cd7d957d1920994da389f490c89", 16),
            new biginteger("c0a0758cdf14256f78d4708c86becdead1b50ad4ad6c5c703e2168fbf37884cb", 16),
            new biginteger("f01734d7960ea60070f1b06f2bb81bfac48ff192ae18451d5e56c734a5aab8a5", 16),
            new biginteger("b54bb9edff22051d9ee60f9351a48591b6500a319429c069a3e335a1d6171391", 16),
            new biginteger("d3d83daf2a0cecd3367ae6f8ae1aeb82e9ac2f816c6fc483533d8297dd7884cd", 16),
            new biginteger("b8f52fc6f38593dabb661d3f50f8897f8106eee68b1bce78a95b132b4e5b5d19", 16));

        //
        // intermediate keys.
        //
        rsapublickeyspec intpubkeyspec = new rsapublickeyspec(
            new biginteger("8de0d113c5e736969c8d2b047a243f8fe18edad64cde9e842d3669230ca486f7cfdde1f8eec54d1905fff04acc85e61093e180cadc6cea407f193d44bb0e9449b8dbb49784cd9e36260c39e06a947299978c6ed8300724e887198cfede20f3fbde658fa2bd078be946a392bd349f2b49c486e20c405588e306706c9017308e69", 16),
            new biginteger("ffff", 16));


        rsaprivatecrtkeyspec intprivkeyspec = new rsaprivatecrtkeyspec(
            new biginteger("8de0d113c5e736969c8d2b047a243f8fe18edad64cde9e842d3669230ca486f7cfdde1f8eec54d1905fff04acc85e61093e180cadc6cea407f193d44bb0e9449b8dbb49784cd9e36260c39e06a947299978c6ed8300724e887198cfede20f3fbde658fa2bd078be946a392bd349f2b49c486e20c405588e306706c9017308e69", 16),
            new biginteger("ffff", 16),
            new biginteger("7deb1b194a85bcfd29cf871411468adbc987650903e3bacc8338c449ca7b32efd39ffc33bc84412fcd7df18d23ce9d7c25ea910b1ae9985373e0273b4dca7f2e0db3b7314056ac67fd277f8f89cf2fd73c34c6ca69f9ba477143d2b0e2445548aa0b4a8473095182631da46844c356f5e5c7522eb54b5a33f11d730ead9c0cff", 16),
            new biginteger("ef4cede573cea47f83699b814de4302edb60eefe426c52e17bd7870ec7c6b7a24fe55282ebb73775f369157726fcfb988def2b40350bdca9e5b418340288f649", 16),
            new biginteger("97c7737d1b9a0088c3c7b528539247fd2a1593e7e01cef18848755be82f4a45aa093276cb0cbf118cb41117540a78f3fc471ba5d69f0042274defc9161265721", 16),
            new biginteger("6c641094e24d172728b8da3c2777e69adfd0839085be7e38c7c4a2dd00b1ae969f2ec9d23e7e37090fcd449a40af0ed463fe1c612d6810d6b4f58b7bfa31eb5f", 16),
            new biginteger("70b7123e8e69dfa76feb1236d0a686144b00e9232ed52b73847e74ef3af71fb45ccb24261f40d27f98101e230cf27b977a5d5f1f15f6cf48d5cb1da2a3a3b87f", 16),
            new biginteger("e38f5750d97e270996a286df2e653fd26c242106436f5bab0f4c7a9e654ce02665d5a281f2c412456f2d1fa26586ef04a9adac9004ca7f913162cb28e13bf40d", 16));

        //
        // ca keys
        //
        rsapublickeyspec capubkeyspec = new rsapublickeyspec(
            new biginteger("b259d2d6e627a768c94be36164c2d9fc79d97aab9253140e5bf17751197731d6f7540d2509e7b9ffee0a70a6e26d56e92d2edd7f85aba85600b69089f35f6bdbf3c298e05842535d9f064e6b0391cb7d306e0a2d20c4dfb4e7b49a9640bdea26c10ad69c3f05007ce2513cee44cfe01998e62b6c3637d3fc0391079b26ee36d5", 16),
            new biginteger("11", 16));

        rsaprivatecrtkeyspec   caprivkeyspec = new rsaprivatecrtkeyspec(
            new biginteger("b259d2d6e627a768c94be36164c2d9fc79d97aab9253140e5bf17751197731d6f7540d2509e7b9ffee0a70a6e26d56e92d2edd7f85aba85600b69089f35f6bdbf3c298e05842535d9f064e6b0391cb7d306e0a2d20c4dfb4e7b49a9640bdea26c10ad69c3f05007ce2513cee44cfe01998e62b6c3637d3fc0391079b26ee36d5", 16),
            new biginteger("11", 16),
            new biginteger("92e08f83cc9920746989ca5034dcb384a094fb9c5a6288fcc4304424ab8f56388f72652d8fafc65a4b9020896f2cde297080f2a540e7b7ce5af0b3446e1258d1dd7f245cf54124b4c6e17da21b90a0ebd22605e6f45c9f136d7a13eaac1c0f7487de8bd6d924972408ebb58af71e76fd7b012a8d0e165f3ae2e5077a8648e619", 16),
            new biginteger("f75e80839b9b9379f1cf1128f321639757dba514642c206bbbd99f9a4846208b3e93fbbe5e0527cc59b1d4b929d9555853004c7c8b30ee6a213c3d1bb7415d03", 16),
            new biginteger("b892d9ebdbfc37e397256dd8a5d3123534d1f03726284743ddc6be3a709edb696fc40c7d902ed804c6eee730eee3d5b20bf6bd8d87a296813c87d3b3cc9d7947", 16),
            new biginteger("1d1a2d3ca8e52068b3094d501c9a842fec37f54db16e9a67070a8b3f53cc03d4257ad252a1a640eadd603724d7bf3737914b544ae332eedf4f34436cac25ceb5", 16),
            new biginteger("6c929e4e81672fef49d9c825163fec97c4b7ba7acb26c0824638ac22605d7201c94625770984f78a56e6e25904fe7db407099cad9b14588841b94f5ab498dded", 16),
            new biginteger("dae7651ee69ad1d081ec5e7188ae126f6004ff39556bde90e0b870962fa7b926d070686d8244fe5a9aa709a95686a104614834b0ada4b10f53197a5cb4c97339", 16));



        //
        // set up the keys
        //
        keyfactory          fact = keyfactory.getinstance("rsa", "bc");
        privatekey          caprivkey = fact.generateprivate(caprivkeyspec);
        publickey           capubkey = fact.generatepublic(capubkeyspec);
        privatekey          intprivkey = fact.generateprivate(intprivkeyspec);
        publickey           intpubkey = fact.generatepublic(intpubkeyspec);
        privatekey          privkey = fact.generateprivate(privkeyspec);
        publickey           pubkey = fact.generatepublic(pubkeyspec);

        certificate[] chain = new certificate[3];

        chain[2] = createmastercert(capubkey, caprivkey);
        chain[1] = createintermediatecert(intpubkey, caprivkey, (x509certificate)chain[2]);
        chain[0] = createcert(pubkey, intprivkey, intpubkey);

        //
        // add the friendly name for the private key
        //
        pkcs12bagattributecarrier   bagattr = (pkcs12bagattributecarrier)privkey;

        //
        // this is also optional - in the sense that if you leave this
        // out the keystore will add it automatically, note though that
        // for the browser to recognise which certificate the private key
        // is associated with you should at least use the pkcs_9_localkeyid
        // oid and set it to the same as you do for the private key's
        // corresponding certificate.
        //
        bagattr.setbagattribute(
            pkcsobjectidentifiers.pkcs_9_at_friendlyname,
            new derbmpstring("eric's key"));
        bagattr.setbagattribute(
            pkcsobjectidentifiers.pkcs_9_at_localkeyid,
            new subjectkeyidentifierstructure(pubkey));

        //
        // store the key and the certificate chain
        //
        keystore store = keystore.getinstance("pkcs12", "bc");

        store.load(null, null);

        //
        // if you haven't set the friendly name and local key id above
        // the name below will be the name of the key
        //
        store.setkeyentry("eric's key", privkey, null, chain);

        fileoutputstream fout = new fileoutputstream("id.p12");

        store.store(fout, passwd);
        
        fout.close();
    }
}
