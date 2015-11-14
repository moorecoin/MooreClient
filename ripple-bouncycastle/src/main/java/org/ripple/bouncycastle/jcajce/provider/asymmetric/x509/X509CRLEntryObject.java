package org.ripple.bouncycastle.jcajce.provider.asymmetric.x509;

import java.io.ioexception;
import java.math.biginteger;
import java.security.cert.crlexception;
import java.security.cert.x509crlentry;
import java.util.date;
import java.util.enumeration;
import java.util.hashset;
import java.util.set;

import javax.security.auth.x500.x500principal;

import org.ripple.bouncycastle.asn1.asn1encoding;
import org.ripple.bouncycastle.asn1.asn1enumerated;
import org.ripple.bouncycastle.asn1.asn1inputstream;
import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.util.asn1dump;
import org.ripple.bouncycastle.asn1.x500.x500name;
import org.ripple.bouncycastle.asn1.x509.crlreason;
import org.ripple.bouncycastle.asn1.x509.extension;
import org.ripple.bouncycastle.asn1.x509.extensions;
import org.ripple.bouncycastle.asn1.x509.generalname;
import org.ripple.bouncycastle.asn1.x509.generalnames;
import org.ripple.bouncycastle.asn1.x509.tbscertlist;
import org.ripple.bouncycastle.asn1.x509.x509extension;

/**
 * the following extensions are listed in rfc 2459 as relevant to crl entries
 * 
 * reasoncode hode instruction code invalidity date certificate issuer
 * (critical)
 */
class x509crlentryobject extends x509crlentry
{
    private tbscertlist.crlentry c;

    private x500name certificateissuer;
    private int           hashvalue;
    private boolean       ishashvalueset;

    public x509crlentryobject(tbscertlist.crlentry c)
    {
        this.c = c;
        this.certificateissuer = null;
    }

    /**
     * constructor for crlentries of indirect crls. if <code>isindirect</code>
     * is <code>false</code> {@link #getcertificateissuer()} will always
     * return <code>null</code>, <code>previouscertificateissuer</code> is
     * ignored. if this <code>isindirect</code> is specified and this crlentry
     * has no certificate issuer crl entry extension
     * <code>previouscertificateissuer</code> is returned by
     * {@link #getcertificateissuer()}.
     * 
     * @param c
     *            tbscertlist.crlentry object.
     * @param isindirect
     *            <code>true</code> if the corresponding crl is a indirect
     *            crl.
     * @param previouscertificateissuer
     *            certificate issuer of the previous crlentry.
     */
    public x509crlentryobject(
        tbscertlist.crlentry c,
        boolean isindirect,
        x500name previouscertificateissuer)
    {
        this.c = c;
        this.certificateissuer = loadcertificateissuer(isindirect, previouscertificateissuer);
    }

    /**
     * will return true if any extensions are present and marked as critical as
     * we currently don't handle any extensions!
     */
    public boolean hasunsupportedcriticalextension()
    {
        set extns = getcriticalextensionoids();

        return extns != null && !extns.isempty();
    }

    private x500name loadcertificateissuer(boolean isindirect, x500name previouscertificateissuer)
    {
        if (!isindirect)
        {
            return null;
        }

        extension ext = getextension(extension.certificateissuer);
        if (ext == null)
        {
            return previouscertificateissuer;
        }

        try
        {
            generalname[] names = generalnames.getinstance(ext.getparsedvalue()).getnames();
            for (int i = 0; i < names.length; i++)
            {
                if (names[i].gettagno() == generalname.directoryname)
                {
                    return x500name.getinstance(names[i].getname());
                }
            }
            return null;
        }
        catch (exception e)
        {
            return null;
        }
    }

    public x500principal getcertificateissuer()
    {
        if (certificateissuer == null)
        {
            return null;
        }
        try
        {
            return new x500principal(certificateissuer.getencoded());
        }
        catch (ioexception e)
        {
            return null;
        }
    }

    private set getextensionoids(boolean critical)
    {
        extensions extensions = c.getextensions();

        if (extensions != null)
        {
            set set = new hashset();
            enumeration e = extensions.oids();

            while (e.hasmoreelements())
            {
                asn1objectidentifier oid = (asn1objectidentifier) e.nextelement();
                extension ext = extensions.getextension(oid);

                if (critical == ext.iscritical())
                {
                    set.add(oid.getid());
                }
            }

            return set;
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

    private extension getextension(asn1objectidentifier oid)
    {
        extensions exts = c.getextensions();

        if (exts != null)
        {
            return exts.getextension(oid);
        }

        return null;
    }

    public byte[] getextensionvalue(string oid)
    {
        extension ext = getextension(new asn1objectidentifier(oid));

        if (ext != null)
        {
            try
            {
                return ext.getextnvalue().getencoded();
            }
            catch (exception e)
            {
                throw new runtimeexception("error encoding " + e.tostring());
            }
        }

        return null;
    }

    /**
     * cache the hashcode value - calculating it with the standard method.
     * @return  calculated hashcode.
     */
    public int hashcode()
    {
        if (!ishashvalueset)
        {
            hashvalue = super.hashcode();
            ishashvalueset = true;
        }

        return hashvalue;
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

    public biginteger getserialnumber()
    {
        return c.getusercertificate().getvalue();
    }

    public date getrevocationdate()
    {
        return c.getrevocationdate().getdate();
    }

    public boolean hasextensions()
    {
        return c.getextensions() != null;
    }

    public string tostring()
    {
        stringbuffer buf = new stringbuffer();
        string nl = system.getproperty("line.separator");

        buf.append("      usercertificate: ").append(this.getserialnumber()).append(nl);
        buf.append("       revocationdate: ").append(this.getrevocationdate()).append(nl);
        buf.append("       certificateissuer: ").append(this.getcertificateissuer()).append(nl);

        extensions extensions = c.getextensions();

        if (extensions != null)
        {
            enumeration e = extensions.oids();
            if (e.hasmoreelements())
            {
                buf.append("   crlentryextensions:").append(nl);

                while (e.hasmoreelements())
                {
                    asn1objectidentifier oid = (asn1objectidentifier)e.nextelement();
                    extension ext = extensions.getextension(oid);
                    if (ext.getextnvalue() != null)
                    {
                        byte[]                  octs = ext.getextnvalue().getoctets();
                        asn1inputstream din = new asn1inputstream(octs);
                        buf.append("                       critical(").append(ext.iscritical()).append(") ");
                        try
                        {
                            if (oid.equals(x509extension.reasoncode))
                            {
                                buf.append(crlreason.getinstance(asn1enumerated.getinstance(din.readobject()))).append(nl);
                            }
                            else if (oid.equals(x509extension.certificateissuer))
                            {
                                buf.append("certificate issuer: ").append(generalnames.getinstance(din.readobject())).append(nl);
                            }
                            else 
                            {
                                buf.append(oid.getid());
                                buf.append(" value = ").append(asn1dump.dumpasstring(din.readobject())).append(nl);
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
        }

        return buf.tostring();
    }
}
