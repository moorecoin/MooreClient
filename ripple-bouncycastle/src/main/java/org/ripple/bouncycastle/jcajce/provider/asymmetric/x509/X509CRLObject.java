package org.ripple.bouncycastle.jcajce.provider.asymmetric.x509;

import java.io.ioexception;
import java.math.biginteger;
import java.security.invalidkeyexception;
import java.security.nosuchalgorithmexception;
import java.security.nosuchproviderexception;
import java.security.principal;
import java.security.publickey;
import java.security.signature;
import java.security.signatureexception;
import java.security.cert.crlexception;
import java.security.cert.certificate;
import java.security.cert.certificateencodingexception;
import java.security.cert.x509crl;
import java.security.cert.x509crlentry;
import java.security.cert.x509certificate;
import java.util.collections;
import java.util.date;
import java.util.enumeration;
import java.util.hashset;
import java.util.iterator;
import java.util.set;

import javax.security.auth.x500.x500principal;

import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1encoding;
import org.ripple.bouncycastle.asn1.asn1inputstream;
import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.asn1octetstring;
import org.ripple.bouncycastle.asn1.util.asn1dump;
import org.ripple.bouncycastle.asn1.x500.x500name;
import org.ripple.bouncycastle.asn1.x509.crldistpoint;
import org.ripple.bouncycastle.asn1.x509.crlnumber;
import org.ripple.bouncycastle.asn1.x509.certificatelist;
import org.ripple.bouncycastle.asn1.x509.extension;
import org.ripple.bouncycastle.asn1.x509.extensions;
import org.ripple.bouncycastle.asn1.x509.generalnames;
import org.ripple.bouncycastle.asn1.x509.issuingdistributionpoint;
import org.ripple.bouncycastle.asn1.x509.tbscertlist;
import org.ripple.bouncycastle.jce.x509principal;
import org.ripple.bouncycastle.jce.provider.bouncycastleprovider;
import org.ripple.bouncycastle.jce.provider.rfc3280certpathutilities;
import org.ripple.bouncycastle.util.encoders.hex;

/**
 * the following extensions are listed in rfc 2459 as relevant to crls
 *
 * authority key identifier
 * issuer alternative name
 * crl number
 * delta crl indicator (critical)
 * issuing distribution point (critical)
 */
class x509crlobject
    extends x509crl
{
    private certificatelist c;
    private string sigalgname;
    private byte[] sigalgparams;
    private boolean isindirect;

    static boolean isindirectcrl(x509crl crl)
        throws crlexception
    {
        try
        {
            byte[] idp = crl.getextensionvalue(extension.issuingdistributionpoint.getid());
            return idp != null
                && issuingdistributionpoint.getinstance(asn1octetstring.getinstance(idp).getoctets()).isindirectcrl();
        }
        catch (exception e)
        {
            throw new extcrlexception(
                    "exception reading issuingdistributionpoint", e);
        }
    }

    public x509crlobject(
        certificatelist c)
        throws crlexception
    {
        this.c = c;
        
        try
        {
            this.sigalgname = x509signatureutil.getsignaturename(c.getsignaturealgorithm());
            
            if (c.getsignaturealgorithm().getparameters() != null)
            {
                this.sigalgparams = ((asn1encodable)c.getsignaturealgorithm().getparameters()).toasn1primitive().getencoded(asn1encoding.der);
            }
            else
            {
                this.sigalgparams = null;
            }

            this.isindirect = isindirectcrl(this);
        }
        catch (exception e)
        {
            throw new crlexception("crl contents invalid: " + e);
        }
    }

    /**
     * will return true if any extensions are present and marked
     * as critical as we currently dont handle any extensions!
     */
    public boolean hasunsupportedcriticalextension()
    {
        set extns = getcriticalextensionoids();

        if (extns == null)
        {
            return false;
        }

        extns.remove(rfc3280certpathutilities.issuing_distribution_point);
        extns.remove(rfc3280certpathutilities.delta_crl_indicator);

        return !extns.isempty();
    }

    private set getextensionoids(boolean critical)
    {
        if (this.getversion() == 2)
        {
            extensions extensions = c.gettbscertlist().getextensions();

            if (extensions != null)
            {
                set set = new hashset();
                enumeration e = extensions.oids();

                while (e.hasmoreelements())
                {
                    asn1objectidentifier oid = (asn1objectidentifier)e.nextelement();
                    extension ext = extensions.getextension(oid);

                    if (critical == ext.iscritical())
                    {
                        set.add(oid.getid());
                    }
                }

                return set;
            }
        }

        return null;
    }

    public set getcriticalextensionoids()
    {
        return getextensionoids(true);
    }

    public set getnoncriticalextensionoids()
    {
        return getextensionoids(false);
    }

    public byte[] getextensionvalue(string oid)
    {
        extensions exts = c.gettbscertlist().getextensions();

        if (exts != null)
        {
            extension ext = exts.getextension(new asn1objectidentifier(oid));

            if (ext != null)
            {
                try
                {
                    return ext.getextnvalue().getencoded();
                }
                catch (exception e)
                {
                    throw new illegalstateexception("error parsing " + e.tostring());
                }
            }
        }

        return null;
    }

    public byte[] getencoded()
        throws crlexception
    {
        try
        {
            return c.getencoded(asn1encoding.der);
        }
        catch (ioexception e)
        {
            throw new crlexception(e.tostring());
        }
    }

    public void verify(publickey key)
        throws crlexception,  nosuchalgorithmexception,
            invalidkeyexception, nosuchproviderexception, signatureexception
    {
        verify(key, bouncycastleprovider.provider_name);
    }

    public void verify(publickey key, string sigprovider)
        throws crlexception, nosuchalgorithmexception,
            invalidkeyexception, nosuchproviderexception, signatureexception
    {
        if (!c.getsignaturealgorithm().equals(c.gettbscertlist().getsignature()))
        {
            throw new crlexception("signature algorithm on certificatelist does not match tbscertlist.");
        }

        signature sig;

        if (sigprovider != null)
        {
            sig = signature.getinstance(getsigalgname(), sigprovider);
        }
        else
        {
            sig = signature.getinstance(getsigalgname());
        }

        sig.initverify(key);
        sig.update(this.gettbscertlist());

        if (!sig.verify(this.getsignature()))
        {
            throw new signatureexception("crl does not verify with supplied public key.");
        }
    }

    public int getversion()
    {
        return c.getversionnumber();
    }

    public principal getissuerdn()
    {
        return new x509principal(x500name.getinstance(c.getissuer().toasn1primitive()));
    }

    public x500principal getissuerx500principal()
    {
        try
        {
            return new x500principal(c.getissuer().getencoded());
        }
        catch (ioexception e)
        {
            throw new illegalstateexception("can't encode issuer dn");
        }
    }

    public date getthisupdate()
    {
        return c.getthisupdate().getdate();
    }

    public date getnextupdate()
    {
        if (c.getnextupdate() != null)
        {
            return c.getnextupdate().getdate();
        }

        return null;
    }
 
    private set loadcrlentries()
    {
        set entryset = new hashset();
        enumeration certs = c.getrevokedcertificateenumeration();

        x500name previouscertificateissuer = null; // the issuer
        while (certs.hasmoreelements())
        {
            tbscertlist.crlentry entry = (tbscertlist.crlentry)certs.nextelement();
            x509crlentryobject crlentry = new x509crlentryobject(entry, isindirect, previouscertificateissuer);
            entryset.add(crlentry);
            if (isindirect && entry.hasextensions())
            {
                extension currentcaname = entry.getextensions().getextension(extension.certificateissuer);

                if (currentcaname != null)
                {
                    previouscertificateissuer = x500name.getinstance(generalnames.getinstance(currentcaname.getparsedvalue()).getnames()[0].getname());
                }
            }
        }

        return entryset;
    }

    public x509crlentry getrevokedcertificate(biginteger serialnumber)
    {
        enumeration certs = c.getrevokedcertificateenumeration();

        x500name previouscertificateissuer = null; // the issuer
        while (certs.hasmoreelements())
        {
            tbscertlist.crlentry entry = (tbscertlist.crlentry)certs.nextelement();

            if (serialnumber.equals(entry.getusercertificate().getvalue()))
            {
                return new x509crlentryobject(entry, isindirect, previouscertificateissuer);
            }

            if (isindirect && entry.hasextensions())
            {
                extension currentcaname = entry.getextensions().getextension(extension.certificateissuer);

                if (currentcaname != null)
                {
                    previouscertificateissuer = x500name.getinstance(generalnames.getinstance(currentcaname.getparsedvalue()).getnames()[0].getname());
                }
            }
        }

        return null;
    }

    public set getrevokedcertificates()
    {
        set entryset = loadcrlentries();

        if (!entryset.isempty())
        {
            return collections.unmodifiableset(entryset);
        }

        return null;
    }

    public byte[] gettbscertlist()
        throws crlexception
    {
        try
        {
            return c.gettbscertlist().getencoded("der");
        }
        catch (ioexception e)
        {
            throw new crlexception(e.tostring());
        }
    }

    public byte[] getsignature()
    {
        return c.getsignature().getbytes();
    }

    public string getsigalgname()
    {
        return sigalgname;
    }

    public string getsigalgoid()
    {
        return c.getsignaturealgorithm().getalgorithm().getid();
    }

    public byte[] getsigalgparams()
    {
        if (sigalgparams != null)
        {
            byte[] tmp = new byte[sigalgparams.length];
            
            system.arraycopy(sigalgparams, 0, tmp, 0, tmp.length);
            
            return tmp;
        }
        
        return null;
    }

    /**
     * returns a string representation of this crl.
     *
     * @return a string representation of this crl.
     */
    public string tostring()
    {
        stringbuffer buf = new stringbuffer();
        string nl = system.getproperty("line.separator");

        buf.append("              version: ").append(this.getversion()).append(
            nl);
        buf.append("             issuerdn: ").append(this.getissuerdn())
            .append(nl);
        buf.append("          this update: ").append(this.getthisupdate())
            .append(nl);
        buf.append("          next update: ").append(this.getnextupdate())
            .append(nl);
        buf.append("  signature algorithm: ").append(this.getsigalgname())
            .append(nl);

        byte[] sig = this.getsignature();

        buf.append("            signature: ").append(
            new string(hex.encode(sig, 0, 20))).append(nl);
        for (int i = 20; i < sig.length; i += 20)
        {
            if (i < sig.length - 20)
            {
                buf.append("                       ").append(
                    new string(hex.encode(sig, i, 20))).append(nl);
            }
            else
            {
                buf.append("                       ").append(
                    new string(hex.encode(sig, i, sig.length - i))).append(nl);
            }
        }

        extensions extensions = c.gettbscertlist().getextensions();

        if (extensions != null)
        {
            enumeration e = extensions.oids();

            if (e.hasmoreelements())
            {
                buf.append("           extensions: ").append(nl);
            }

            while (e.hasmoreelements())
            {
                asn1objectidentifier oid = (asn1objectidentifier) e.nextelement();
                extension ext = extensions.getextension(oid);

                if (ext.getextnvalue() != null)
                {
                    byte[] octs = ext.getextnvalue().getoctets();
                    asn1inputstream din = new asn1inputstream(octs);
                    buf.append("                       critical(").append(
                        ext.iscritical()).append(") ");
                    try
                    {
                        if (oid.equals(extension.crlnumber))
                        {
                            buf.append(
                                new crlnumber(asn1integer.getinstance(
                                    din.readobject()).getpositivevalue()))
                                .append(nl);
                        }
                        else if (oid.equals(extension.deltacrlindicator))
                        {
                            buf.append(
                                "base crl: "
                                    + new crlnumber(asn1integer.getinstance(
                                        din.readobject()).getpositivevalue()))
                                .append(nl);
                        }
                        else if (oid
                            .equals(extension.issuingdistributionpoint))
                        {
                            buf.append(
                               issuingdistributionpoint.getinstance(din.readobject())).append(nl);
                        }
                        else if (oid
                            .equals(extension.crldistributionpoints))
                        {
                            buf.append(
                                crldistpoint.getinstance(din.readobject())).append(nl);
                        }
                        else if (oid.equals(extension.freshestcrl))
                        {
                            buf.append(
                                crldistpoint.getinstance(din.readobject())).append(nl);
                        }
                        else
                        {
                            buf.append(oid.getid());
                            buf.append(" value = ").append(
                                asn1dump.dumpasstring(din.readobject()))
                                .append(nl);
                        }
                    }
                    catch (exception ex)
                    {
                        buf.append(oid.getid());
                        buf.append(" value = ").append("*****").append(nl);
                    }
                }
                else
                {
                    buf.append(nl);
                }
            }
        }
        set set = getrevokedcertificates();
        if (set != null)
        {
            iterator it = set.iterator();
            while (it.hasnext())
            {
                buf.append(it.next());
                buf.append(nl);
            }
        }
        return buf.tostring();
    }

    /**
     * checks whether the given certificate is on this crl.
     *
     * @param cert the certificate to check for.
     * @return true if the given certificate is on this crl,
     * false otherwise.
     */
    public boolean isrevoked(certificate cert)
    {
        if (!cert.gettype().equals("x.509"))
        {
            throw new runtimeexception("x.509 crl used with non x.509 cert");
        }

        tbscertlist.crlentry[] certs = c.getrevokedcertificates();

        x500name caname = c.getissuer();

        if (certs != null)
        {
            biginteger serial = ((x509certificate)cert).getserialnumber();

            for (int i = 0; i < certs.length; i++)
            {
                if (isindirect && certs[i].hasextensions())
                {
                    extension currentcaname = certs[i].getextensions().getextension(extension.certificateissuer);

                    if (currentcaname != null)
                    {
                        caname = x500name.getinstance(generalnames.getinstance(currentcaname.getparsedvalue()).getnames()[0].getname());
                    }
                }

                if (certs[i].getusercertificate().getvalue().equals(serial))
                {
                    x500name issuer;

                    if (cert instanceof  x509certificate)
                    {
                        issuer = x500name.getinstance(((x509certificate)cert).getissuerx500principal().getencoded());
                    }
                    else
                    {
                        try
                        {
                            issuer = org.ripple.bouncycastle.asn1.x509.certificate.getinstance(cert.getencoded()).getissuer();
                        }
                        catch (certificateencodingexception e)
                        {
                            throw new runtimeexception("cannot process certificate");
                        }
                    }

                    if (!caname.equals(issuer))
                    {
                        return false;
                    }

                    return true;
                }
            }
        }

        return false;
    }
}

