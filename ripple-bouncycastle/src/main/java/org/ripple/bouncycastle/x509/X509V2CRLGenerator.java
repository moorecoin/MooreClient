package org.ripple.bouncycastle.x509;

import java.io.ioexception;
import java.math.biginteger;
import java.security.generalsecurityexception;
import java.security.invalidkeyexception;
import java.security.nosuchalgorithmexception;
import java.security.nosuchproviderexception;
import java.security.privatekey;
import java.security.securerandom;
import java.security.signatureexception;
import java.security.cert.crlexception;
import java.security.cert.x509crl;
import java.security.cert.x509crlentry;
import java.util.date;
import java.util.iterator;
import java.util.set;

import javax.security.auth.x500.x500principal;

import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1generalizedtime;
import org.ripple.bouncycastle.asn1.asn1inputstream;
import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.derbitstring;
import org.ripple.bouncycastle.asn1.derobjectidentifier;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.x509.algorithmidentifier;
import org.ripple.bouncycastle.asn1.x509.certificatelist;
import org.ripple.bouncycastle.asn1.x509.extensions;
import org.ripple.bouncycastle.asn1.x509.tbscertlist;
import org.ripple.bouncycastle.asn1.x509.time;
import org.ripple.bouncycastle.asn1.x509.v2tbscertlistgenerator;
import org.ripple.bouncycastle.asn1.x509.x509extensions;
import org.ripple.bouncycastle.asn1.x509.x509extensionsgenerator;
import org.ripple.bouncycastle.asn1.x509.x509name;
import org.ripple.bouncycastle.jce.x509principal;
import org.ripple.bouncycastle.jce.provider.x509crlobject;

/**
 * class to produce an x.509 version 2 crl.
 *  @deprecated use org.bouncycastle.cert.x509v2crlbuilder.
 */
public class x509v2crlgenerator
{
    private v2tbscertlistgenerator      tbsgen;
    private derobjectidentifier         sigoid;
    private algorithmidentifier         sigalgid;
    private string                      signaturealgorithm;
    private x509extensionsgenerator     extgenerator;

    public x509v2crlgenerator()
    {
        tbsgen = new v2tbscertlistgenerator();
        extgenerator = new x509extensionsgenerator();
    }

    /**
     * reset the generator
     */
    public void reset()
    {
        tbsgen = new v2tbscertlistgenerator();
        extgenerator.reset();
    }

    /**
     * set the issuer distinguished name - the issuer is the entity whose private key is used to sign the
     * certificate.
     */
    public void setissuerdn(
        x500principal   issuer)
    {
        try
        {
            tbsgen.setissuer(new x509principal(issuer.getencoded()));
        }
        catch (ioexception e)
        {
            throw new illegalargumentexception("can't process principal: " + e);
        }
    }

    /**
     * set the issuer distinguished name - the issuer is the entity whose private key is used to sign the
     * certificate.
     */
    public void setissuerdn(
        x509name   issuer)
    {
        tbsgen.setissuer(issuer);
    }

    public void setthisupdate(
        date    date)
    {
        tbsgen.setthisupdate(new time(date));
    }

    public void setnextupdate(
        date    date)
    {
        tbsgen.setnextupdate(new time(date));
    }

    /**
     * reason being as indicated by crlreason, i.e. crlreason.keycompromise
     * or 0 if crlreason is not to be used
     **/
    public void addcrlentry(biginteger usercertificate, date revocationdate, int reason)
    {
        tbsgen.addcrlentry(new asn1integer(usercertificate), new time(revocationdate), reason);
    }

    /**
     * add a crl entry with an invalidity date extension as well as a crlreason extension.
     * reason being as indicated by crlreason, i.e. crlreason.keycompromise
     * or 0 if crlreason is not to be used
     **/
    public void addcrlentry(biginteger usercertificate, date revocationdate, int reason, date invaliditydate)
    {
        tbsgen.addcrlentry(new asn1integer(usercertificate), new time(revocationdate), reason, new asn1generalizedtime(invaliditydate));
    }
   
    /**
     * add a crl entry with extensions.
     **/
    public void addcrlentry(biginteger usercertificate, date revocationdate, x509extensions extensions)
    {
        tbsgen.addcrlentry(new asn1integer(usercertificate), new time(revocationdate), extensions.getinstance(extensions));
    }
    
    /**
     * add the crlentry objects contained in a previous crl.
     * 
     * @param other the x509crl to source the other entries from. 
     */
    public void addcrl(x509crl other)
        throws crlexception
    {
        set revocations = other.getrevokedcertificates();

        if (revocations != null)
        {
            iterator it = revocations.iterator();
            while (it.hasnext())
            {
                x509crlentry entry = (x509crlentry)it.next();

                asn1inputstream ain = new asn1inputstream(entry.getencoded());

                try
                {
                    tbsgen.addcrlentry(asn1sequence.getinstance(ain.readobject()));
                }
                catch (ioexception e)
                {
                    throw new crlexception("exception processing encoding of crl: " + e.tostring());
                }
            }
        }
    }
    
    /**
     * set the signature algorithm. this can be either a name or an oid, names
     * are treated as case insensitive.
     * 
     * @param signaturealgorithm string representation of the algorithm name.
     */
    public void setsignaturealgorithm(
        string  signaturealgorithm)
    {
        this.signaturealgorithm = signaturealgorithm;

        try
        {
            sigoid = x509util.getalgorithmoid(signaturealgorithm);
        }
        catch (exception e)
        {
            throw new illegalargumentexception("unknown signature type requested");
        }

        sigalgid = x509util.getsigalgid(sigoid, signaturealgorithm);

        tbsgen.setsignature(sigalgid);
    }

    /**
     * add a given extension field for the standard extensions tag (tag 0)
     */
    public void addextension(
        string          oid,
        boolean         critical,
        asn1encodable    value)
    {
        this.addextension(new derobjectidentifier(oid), critical, value);
    }

    /**
     * add a given extension field for the standard extensions tag (tag 0)
     */
    public void addextension(
        derobjectidentifier oid,
        boolean             critical,
        asn1encodable value)
    {
        extgenerator.addextension(new asn1objectidentifier(oid.getid()), critical, value);
    }

    /**
     * add a given extension field for the standard extensions tag (tag 0)
     */
    public void addextension(
        string          oid,
        boolean         critical,
        byte[]          value)
    {
        this.addextension(new derobjectidentifier(oid), critical, value);
    }

    /**
     * add a given extension field for the standard extensions tag (tag 0)
     */
    public void addextension(
        derobjectidentifier oid,
        boolean             critical,
        byte[]              value)
    {
        extgenerator.addextension(new asn1objectidentifier(oid.getid()), critical, value);
    }

    /**
     * generate an x509 crl, based on the current issuer and subject
     * using the default provider "bc".
     * @deprecated use generate(key, "bc")
     */
    public x509crl generatex509crl(
        privatekey      key)
        throws securityexception, signatureexception, invalidkeyexception
    {
        try
        {
            return generatex509crl(key, "bc", null);
        }
        catch (nosuchproviderexception e)
        {
            throw new securityexception("bc provider not installed!");
        }
    }

    /**
     * generate an x509 crl, based on the current issuer and subject
     * using the default provider "bc" and an user defined securerandom object as
     * source of randomness.
     * @deprecated use generate(key, random, "bc")
     */
    public x509crl generatex509crl(
        privatekey      key,
        securerandom    random)
        throws securityexception, signatureexception, invalidkeyexception
    {
        try
        {
            return generatex509crl(key, "bc", random);
        }
        catch (nosuchproviderexception e)
        {
            throw new securityexception("bc provider not installed!");
        }
    }

    /**
     * generate an x509 certificate, based on the current issuer and subject
     * using the passed in provider for the signing.
     * @deprecated use generate()
     */
    public x509crl generatex509crl(
        privatekey      key,
        string          provider)
        throws nosuchproviderexception, securityexception, signatureexception, invalidkeyexception
    {
        return generatex509crl(key, provider, null);
    }

    /**
     * generate an x509 crl, based on the current issuer and subject,
     * using the passed in provider for the signing.
     * @deprecated use generate()
     */
    public x509crl generatex509crl(
        privatekey      key,
        string          provider,
        securerandom    random)
        throws nosuchproviderexception, securityexception, signatureexception, invalidkeyexception
    {
        try
        {
            return generate(key, provider, random);
        }
        catch (nosuchproviderexception e)
        {
            throw e;
        }
        catch (signatureexception e)
        {
            throw e;
        }
        catch (invalidkeyexception e)
        {
            throw e;
        }
        catch (generalsecurityexception e)
        {
            throw new securityexception("exception: " + e);
        }
    }
    
    /**
     * generate an x509 crl, based on the current issuer and subject
     * using the default provider.
     * <p>
     * <b>note:</b> this differs from the deprecated method in that the default provider is
     * used - not "bc".
     * </p>
     */
    public x509crl generate(
        privatekey      key)
        throws crlexception, illegalstateexception, nosuchalgorithmexception, signatureexception, invalidkeyexception
    {
        return generate(key, (securerandom)null);
    }

    /**
     * generate an x509 crl, based on the current issuer and subject
     * using the default provider and an user defined securerandom object as
     * source of randomness.
     * <p>
     * <b>note:</b> this differs from the deprecated method in that the default provider is
     * used - not "bc".
     * </p>
     */
    public x509crl generate(
        privatekey      key,
        securerandom    random)
        throws crlexception, illegalstateexception, nosuchalgorithmexception, signatureexception, invalidkeyexception
    {
        tbscertlist tbscrl = generatecertlist();
        byte[] signature;

        try
        {
            signature = x509util.calculatesignature(sigoid, signaturealgorithm, key, random, tbscrl);
        }
        catch (ioexception e)
        {
            throw new extcrlexception("cannot generate crl encoding", e);
        }

        return generatejcaobject(tbscrl, signature);
    }

    /**
     * generate an x509 certificate, based on the current issuer and subject
     * using the passed in provider for the signing.
     */
    public x509crl generate(
        privatekey      key,
        string          provider)
        throws crlexception, illegalstateexception, nosuchproviderexception, nosuchalgorithmexception, signatureexception, invalidkeyexception
    {
        return generate(key, provider, null);
    }

    /**
     * generate an x509 crl, based on the current issuer and subject,
     * using the passed in provider for the signing.
     */
    public x509crl generate(
        privatekey      key,
        string          provider,
        securerandom    random)
        throws crlexception, illegalstateexception, nosuchproviderexception, nosuchalgorithmexception, signatureexception, invalidkeyexception
    {
        tbscertlist tbscrl = generatecertlist();
        byte[] signature;

        try
        {
            signature = x509util.calculatesignature(sigoid, signaturealgorithm, provider, key, random, tbscrl);
        }
        catch (ioexception e)
        {
            throw new extcrlexception("cannot generate crl encoding", e);
        }

        return generatejcaobject(tbscrl, signature);
    }

    private tbscertlist generatecertlist()
    {
        if (!extgenerator.isempty())
        {
            tbsgen.setextensions(extgenerator.generate());
        }

        return tbsgen.generatetbscertlist();
    }

    private x509crl generatejcaobject(tbscertlist tbscrl, byte[] signature)
        throws crlexception
    {
        asn1encodablevector v = new asn1encodablevector();

        v.add(tbscrl);
        v.add(sigalgid);
        v.add(new derbitstring(signature));

        return new x509crlobject(new certificatelist(new dersequence(v)));
    }

    /**
     * return an iterator of the signature names supported by the generator.
     * 
     * @return an iterator containing recognised names.
     */
    public iterator getsignaturealgnames()
    {
        return x509util.getalgnames();
    }

    private static class extcrlexception
        extends crlexception
    {
        throwable cause;

        extcrlexception(string message, throwable cause)
        {
            super(message);
            this.cause = cause;
        }

        public throwable getcause()
        {
            return cause;
        }
    }
}
