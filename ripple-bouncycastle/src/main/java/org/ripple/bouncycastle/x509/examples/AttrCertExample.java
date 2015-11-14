package org.ripple.bouncycastle.x509.examples;

import java.math.biginteger;
import java.security.keyfactory;
import java.security.privatekey;
import java.security.publickey;
import java.security.security;
import java.security.cert.x509certificate;
import java.security.spec.rsaprivatecrtkeyspec;
import java.security.spec.rsapublickeyspec;
import java.util.date;
import java.util.hashtable;
import java.util.vector;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.misc.miscobjectidentifiers;
import org.ripple.bouncycastle.asn1.misc.netscapecerttype;
import org.ripple.bouncycastle.asn1.x509.generalname;
import org.ripple.bouncycastle.jce.x509principal;
import org.ripple.bouncycastle.jce.provider.bouncycastleprovider;
import org.ripple.bouncycastle.x509.attributecertificateholder;
import org.ripple.bouncycastle.x509.attributecertificateissuer;
import org.ripple.bouncycastle.x509.x509attribute;
import org.ripple.bouncycastle.x509.x509v1certificategenerator;
import org.ripple.bouncycastle.x509.x509v2attributecertificate;
import org.ripple.bouncycastle.x509.x509v2attributecertificategenerator;
import org.ripple.bouncycastle.x509.x509v3certificategenerator;

/**
 * a simple example that generates an attribute certificate.
 */
public class attrcertexample
{
    static x509v1certificategenerator  v1certgen = new x509v1certificategenerator();
    static x509v3certificategenerator  v3certgen = new x509v3certificategenerator();
    
    /**
     * we generate the ac issuer's certificate
     */
    public static x509certificate createacissuercert(
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

        v1certgen.setserialnumber(biginteger.valueof(10));
        v1certgen.setissuerdn(new x509principal(issuer));
        v1certgen.setnotbefore(new date(system.currenttimemillis() - 1000l * 60 * 60 * 24 * 30));
        v1certgen.setnotafter(new date(system.currenttimemillis() + (1000l * 60 * 60 * 24 * 30)));
        v1certgen.setsubjectdn(new x509principal(subject));
        v1certgen.setpublickey(pubkey);
        v1certgen.setsignaturealgorithm("sha1withrsaencryption");

        x509certificate cert = v1certgen.generate(privkey);

        cert.checkvalidity(new date());

        cert.verify(pubkey);

        return cert;
    }
    
    /**
     * we generate a certificate signed by our ca's intermediate certficate
     */
    public static x509certificate createclientcert(
        publickey       pubkey,
        privatekey      caprivkey,
        publickey       capubkey)
        throws exception
    {
        //
        // issuer
        //
        string  issuer = "c=au, o=the legion of the bouncy castle, ou=bouncy primary certificate";

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

        v3certgen.setserialnumber(biginteger.valueof(20));
        v3certgen.setissuerdn(new x509principal(issuer));
        v3certgen.setnotbefore(new date(system.currenttimemillis() - 1000l * 60 * 60 * 24 * 30));
        v3certgen.setnotafter(new date(system.currenttimemillis() + (1000l * 60 * 60 * 24 * 30)));
        v3certgen.setsubjectdn(new x509principal(order, attrs));
        v3certgen.setpublickey(pubkey);
        v3certgen.setsignaturealgorithm("sha1withrsaencryption");

        //
        // add the extensions
        //

        v3certgen.addextension(
            miscobjectidentifiers.netscapecerttype,
            false,
            new netscapecerttype(netscapecerttype.objectsigning | netscapecerttype.smime));

        x509certificate cert = v3certgen.generate(caprivkey);

        cert.checkvalidity(new date());

        cert.verify(capubkey);

        return cert;
    }
    
    public static void main(string args[])
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
        privatekey          privkey = fact.generateprivate(privkeyspec);
        publickey           pubkey = fact.generatepublic(pubkeyspec);

        //
        // note in this case we are using the ca certificate for both the client cetificate
        // and the attribute certificate. this is to make the vcode simpler to read, in practice
        // the ca for the attribute certificate should be different to that of the client certificate
        //
        x509certificate     cacert = createacissuercert(capubkey, caprivkey);
        x509certificate     clientcert = createclientcert(pubkey, caprivkey, capubkey);

        // instantiate a new ac generator
        x509v2attributecertificategenerator acgen = new x509v2attributecertificategenerator();

        acgen.reset();

        //
        // holder: here we use the issuerserial form
        //
        acgen.setholder(new attributecertificateholder(clientcert));

        // set the issuer
        acgen.setissuer(new attributecertificateissuer(cacert.getsubjectx500principal()));

        //
        // serial number (as it's an example we don't have to keep track of the
        // serials anyway
        //
        acgen.setserialnumber(new biginteger("1"));

        // not before
        acgen.setnotbefore(new date(system.currenttimemillis() - 50000));

        // not after
        acgen.setnotafter(new date(system.currenttimemillis() + 50000));

        // signature algorithmus
        acgen.setsignaturealgorithm("sha1withrsaencryption");

        // the actual attributes
        generalname rolename = new generalname(generalname.rfc822name, "dau123456789");
        asn1encodablevector rolesyntax = new asn1encodablevector();
        rolesyntax.add(rolename);

        // rolesyntax oid: 2.5.24.72
        x509attribute attributes = new x509attribute("2.5.24.72",
                new dersequence(rolesyntax));

        acgen.addattribute(attributes);

        //      finally create the ac
        x509v2attributecertificate att = (x509v2attributecertificate)acgen
                .generate(caprivkey, "bc");

        //
        // starting here, we parse the newly generated ac
        //

        // holder

        attributecertificateholder h = att.getholder();
        if (h.match(clientcert))
        {
            if (h.getentitynames() != null)
            {
                system.out.println(h.getentitynames().length + " entity names found");
            }
            if (h.getissuer() != null)
            {
                system.out.println(h.getissuer().length + " issuer names found, serial number " + h.getserialnumber());
            }
            system.out.println("matches original client x509 cert");
        }

        // issuer
        
        attributecertificateissuer issuer = att.getissuer();
        if (issuer.match(cacert))
        {
            if (issuer.getprincipals() != null)
            {
                system.out.println(issuer.getprincipals().length + " entity names found");
            }
            system.out.println("matches original ca x509 cert");
        }
        
        // dates
        system.out.println("valid not before: " + att.getnotbefore());
        system.out.println("valid not before: " + att.getnotafter());

        // check the dates, an exception is thrown in checkvalidity()...

        try
        {
            att.checkvalidity();
            att.checkvalidity(new date());
        }
        catch (exception e)
        {
            system.out.println(e);
        }

        // verify

        try
        {
            att.verify(capubkey, "bc");
        }
        catch (exception e)
        {
            system.out.println(e);
        }

        // attribute
        x509attribute[] attribs = att.getattributes();
        system.out.println("cert has " + attribs.length + " attributes:");
        for (int i = 0; i < attribs.length; i++)
        {
            x509attribute a = attribs[i];
            system.out.println("oid: " + a.getoid());
            
            // currently we only check for the presence of a 'rolesyntax' attribute

            if (a.getoid().equals("2.5.24.72"))
            {
                system.out.println("rolesyntax read from cert!");
            }
        }
    }
}