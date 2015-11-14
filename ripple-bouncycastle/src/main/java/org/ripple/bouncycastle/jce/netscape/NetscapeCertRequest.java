package org.ripple.bouncycastle.jce.netscape;

import java.io.bytearrayinputstream;
import java.io.bytearrayoutputstream;
import java.io.ioexception;
import java.security.invalidkeyexception;
import java.security.keyfactory;
import java.security.nosuchalgorithmexception;
import java.security.nosuchproviderexception;
import java.security.privatekey;
import java.security.publickey;
import java.security.securerandom;
import java.security.signature;
import java.security.signatureexception;
import java.security.spec.invalidkeyspecexception;
import java.security.spec.x509encodedkeyspec;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1encoding;
import org.ripple.bouncycastle.asn1.asn1inputstream;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.derbitstring;
import org.ripple.bouncycastle.asn1.deria5string;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.x509.algorithmidentifier;
import org.ripple.bouncycastle.asn1.x509.subjectpublickeyinfo;

/**
 *
 * 
 * handles netscape certificate request (keygen), these are constructed as:
 * <pre><code>
 *   signedpublickeyandchallenge ::= sequence {
 *     publickeyandchallenge    publickeyandchallenge,
 *     signaturealgorithm       algorithmidentifier,
 *     signature                bit string
 *   }
 * </pre>
 *
 * publickey's encoded-format has to be x.509.
 *
 **/
public class netscapecertrequest
    extends asn1object
{
    algorithmidentifier    sigalg;
    algorithmidentifier    keyalg;
    byte        sigbits [];
    string challenge;
    derbitstring content;
    publickey pubkey ;
    
    private static asn1sequence getreq(
        byte[]  r)
        throws ioexception
    {
        asn1inputstream ain = new asn1inputstream(new bytearrayinputstream(r));

        return asn1sequence.getinstance(ain.readobject());
    }

    public netscapecertrequest(
        byte[]  req)
        throws ioexception
    {
        this(getreq(req));
    }

    public netscapecertrequest (asn1sequence spkac)
    {
        try
        {

            //
            // signedpublickeyandchallenge ::= sequence {
            //    publickeyandchallenge    publickeyandchallenge,
            //    signaturealgorithm    algorithmidentifier,
            //    signature        bit string
            // }
            //
            if (spkac.size() != 3)
            {
                throw new illegalargumentexception("invalid spkac (size):"
                        + spkac.size());
            }

            sigalg = new algorithmidentifier((asn1sequence)spkac
                    .getobjectat(1));
            sigbits = ((derbitstring)spkac.getobjectat(2)).getbytes();

            //
            // publickeyandchallenge ::= sequence {
            //    spki            subjectpublickeyinfo,
            //    challenge        ia5string
            // }
            //
            asn1sequence pkac = (asn1sequence)spkac.getobjectat(0);

            if (pkac.size() != 2)
            {
                throw new illegalargumentexception("invalid pkac (len): "
                        + pkac.size());
            }

            challenge = ((deria5string)pkac.getobjectat(1)).getstring();

            //this could be dangerous, as asn.1 decoding/encoding
            //could potentially alter the bytes
            content = new derbitstring(pkac);

            subjectpublickeyinfo pubkeyinfo = new subjectpublickeyinfo(
                    (asn1sequence)pkac.getobjectat(0));

            x509encodedkeyspec xspec = new x509encodedkeyspec(new derbitstring(
                    pubkeyinfo).getbytes());

            keyalg = pubkeyinfo.getalgorithmid();
            pubkey = keyfactory.getinstance(keyalg.getobjectid().getid(), "bc")
                    .generatepublic(xspec);

        }
        catch (exception e)
        {
            throw new illegalargumentexception(e.tostring());
        }
    }

    public netscapecertrequest(
        string challenge,
        algorithmidentifier signing_alg,
        publickey pub_key) throws nosuchalgorithmexception,
            invalidkeyspecexception, nosuchproviderexception
    {

        this.challenge = challenge;
        sigalg = signing_alg;
        pubkey = pub_key;

        asn1encodablevector content_der = new asn1encodablevector();
        content_der.add(getkeyspec());
        //content_der.add(new subjectpublickeyinfo(sigalg, new rsapublickeystructure(pubkey.getmodulus(), pubkey.getpublicexponent()).getderobject()));
        content_der.add(new deria5string(challenge));

        try
        {
            content = new derbitstring(new dersequence(content_der));
        }
        catch (ioexception e)
        {
            throw new invalidkeyspecexception("exception encoding key: " + e.tostring());
        }
    }

    public string getchallenge()
    {
        return challenge;
    }

    public void setchallenge(string value)
    {
        challenge = value;
    }

    public algorithmidentifier getsigningalgorithm()
    {
        return sigalg;
    }

    public void setsigningalgorithm(algorithmidentifier value)
    {
        sigalg = value;
    }

    public algorithmidentifier getkeyalgorithm()
    {
        return keyalg;
    }

    public void setkeyalgorithm(algorithmidentifier value)
    {
        keyalg = value;
    }

    public publickey getpublickey()
    {
        return pubkey;
    }

    public void setpublickey(publickey value)
    {
        pubkey = value;
    }

    public boolean verify(string challenge) throws nosuchalgorithmexception,
            invalidkeyexception, signatureexception, nosuchproviderexception
    {
        if (!challenge.equals(this.challenge))
        {
            return false;
        }

        //
        // verify the signature .. shows the response was generated
        // by someone who knew the associated private key
        //
        signature sig = signature.getinstance(sigalg.getobjectid().getid(),
                "bc");
        sig.initverify(pubkey);
        sig.update(content.getbytes());

        return sig.verify(sigbits);
    }

    public void sign(privatekey priv_key) throws nosuchalgorithmexception,
            invalidkeyexception, signatureexception, nosuchproviderexception,
            invalidkeyspecexception
    {
        sign(priv_key, null);
    }

    public void sign(privatekey priv_key, securerandom rand)
            throws nosuchalgorithmexception, invalidkeyexception,
            signatureexception, nosuchproviderexception,
            invalidkeyspecexception
    {
        signature sig = signature.getinstance(sigalg.getalgorithm().getid(),
                "bc");

        if (rand != null)
        {
            sig.initsign(priv_key, rand);
        }
        else
        {
            sig.initsign(priv_key);
        }

        asn1encodablevector pkac = new asn1encodablevector();

        pkac.add(getkeyspec());
        pkac.add(new deria5string(challenge));

        try
        {
            sig.update(new dersequence(pkac).getencoded(asn1encoding.der));
        }
        catch (ioexception ioe)
        {
            throw new signatureexception(ioe.getmessage());
        }

        sigbits = sig.sign();
    }

    private asn1primitive getkeyspec() throws nosuchalgorithmexception,
            invalidkeyspecexception, nosuchproviderexception
    {
        bytearrayoutputstream baos = new bytearrayoutputstream();

        asn1primitive obj = null;
        try
        {

            baos.write(pubkey.getencoded());
            baos.close();

            asn1inputstream derin = new asn1inputstream(
                    new bytearrayinputstream(baos.tobytearray()));

            obj = derin.readobject();
        }
        catch (ioexception ioe)
        {
            throw new invalidkeyspecexception(ioe.getmessage());
        }
        return obj;
    }

    public asn1primitive toasn1primitive()
    {
        asn1encodablevector spkac = new asn1encodablevector();
        asn1encodablevector pkac = new asn1encodablevector();

        try
        {
            pkac.add(getkeyspec());
        }
        catch (exception e)
        {
            //ignore
        }

        pkac.add(new deria5string(challenge));

        spkac.add(new dersequence(pkac));
        spkac.add(sigalg);
        spkac.add(new derbitstring(sigbits));

        return new dersequence(spkac);
    }
}
