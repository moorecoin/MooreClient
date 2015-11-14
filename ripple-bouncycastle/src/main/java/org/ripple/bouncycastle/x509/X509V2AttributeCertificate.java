package org.ripple.bouncycastle.x509;

import java.io.bytearrayinputstream;
import java.io.ioexception;
import java.io.inputstream;
import java.math.biginteger;
import java.security.invalidkeyexception;
import java.security.nosuchalgorithmexception;
import java.security.nosuchproviderexception;
import java.security.publickey;
import java.security.signature;
import java.security.signatureexception;
import java.security.cert.certificateexception;
import java.security.cert.certificateexpiredexception;
import java.security.cert.certificatenotyetvalidexception;
import java.text.parseexception;
import java.util.arraylist;
import java.util.date;
import java.util.enumeration;
import java.util.hashset;
import java.util.list;
import java.util.set;

import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1encoding;
import org.ripple.bouncycastle.asn1.asn1inputstream;
import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.derbitstring;
import org.ripple.bouncycastle.asn1.x509.attributecertificate;
import org.ripple.bouncycastle.asn1.x509.extension;
import org.ripple.bouncycastle.asn1.x509.extensions;
import org.ripple.bouncycastle.util.arrays;

/**
 * an implementation of a version 2 x.509 attribute certificate.
 * @deprecated use org.bouncycastle.cert.x509attributecertificateholder
 */
public class x509v2attributecertificate
    implements x509attributecertificate
{
    private attributecertificate    cert;
    private date                    notbefore;
    private date                    notafter;

    private static attributecertificate getobject(inputstream in)
        throws ioexception
    {
        try
        {
            return attributecertificate.getinstance(new asn1inputstream(in).readobject());
        }
        catch (ioexception e)
        {
            throw e;
        }
        catch (exception e)
        {
            throw new ioexception("exception decoding certificate structure: " + e.tostring());
        }
    }

    public x509v2attributecertificate(
        inputstream encin)
        throws ioexception
    {
        this(getobject(encin));
    }
    
    public x509v2attributecertificate(
        byte[]  encoded)
        throws ioexception
    {
        this(new bytearrayinputstream(encoded));
    }
    
    x509v2attributecertificate(
        attributecertificate    cert)
        throws ioexception
    {
        this.cert = cert;
        
        try
        {
            this.notafter = cert.getacinfo().getattrcertvalidityperiod().getnotaftertime().getdate();
            this.notbefore = cert.getacinfo().getattrcertvalidityperiod().getnotbeforetime().getdate();
        }
        catch (parseexception e)
        {
            throw new ioexception("invalid data structure in certificate!");
        }
    }
    
    public int getversion()
    {
        return cert.getacinfo().getversion().getvalue().intvalue() + 1;
    }
    
    public biginteger getserialnumber()
    {
        return cert.getacinfo().getserialnumber().getvalue();
    }
    
    public attributecertificateholder getholder()
    {
        return new attributecertificateholder((asn1sequence)cert.getacinfo().getholder().toasn1object());
    }
    
    public attributecertificateissuer getissuer()
    {
        return new attributecertificateissuer(cert.getacinfo().getissuer());
    }
    
    public date getnotbefore()
    {
        return notbefore;
    }
    
    public date getnotafter()
    {
        return notafter;
    }
    
    public boolean[] getissueruniqueid()
    {
        derbitstring    id = cert.getacinfo().getissueruniqueid();

        if (id != null)
        {
            byte[]          bytes = id.getbytes();
            boolean[]       boolid = new boolean[bytes.length * 8 - id.getpadbits()];

            for (int i = 0; i != boolid.length; i++)
            {
                boolid[i] = (bytes[i / 8] & (0x80 >>> (i % 8))) != 0;
            }

            return boolid;
        }
            
        return null;
    }
    
    public void checkvalidity() 
        throws certificateexpiredexception, certificatenotyetvalidexception
    {
        this.checkvalidity(new date());
    }
    
    public void checkvalidity(
        date    date)
        throws certificateexpiredexception, certificatenotyetvalidexception
    {
        if (date.after(this.getnotafter()))
        {
            throw new certificateexpiredexception("certificate expired on " + this.getnotafter());
        }

        if (date.before(this.getnotbefore()))
        {
            throw new certificatenotyetvalidexception("certificate not valid till " + this.getnotbefore());
        }
    }
    
    public byte[] getsignature()
    {
        return cert.getsignaturevalue().getbytes();
    }
    
    public final void verify(
            publickey   key,
            string      provider)
            throws certificateexception, nosuchalgorithmexception,
            invalidkeyexception, nosuchproviderexception, signatureexception
    {
        signature   signature = null;

        if (!cert.getsignaturealgorithm().equals(cert.getacinfo().getsignature()))
        {
            throw new certificateexception("signature algorithm in certificate info not same as outer certificate");
        }

        signature = signature.getinstance(cert.getsignaturealgorithm().getobjectid().getid(), provider);

        signature.initverify(key);

        try
        {
            signature.update(cert.getacinfo().getencoded());
        }
        catch (ioexception e)
        {
            throw new signatureexception("exception encoding certificate info object");
        }

        if (!signature.verify(this.getsignature()))
        {
            throw new invalidkeyexception("public key presented not for certificate signature");
        }
    }
    
    public byte[] getencoded()
        throws ioexception
    {
        return cert.getencoded();
    }

    public byte[] getextensionvalue(string oid) 
    {
        extensions extensions = cert.getacinfo().getextensions();

        if (extensions != null)
        {
            extension ext = extensions.getextension(new asn1objectidentifier(oid));

            if (ext != null)
            {
                try
                {
                    return ext.getextnvalue().getencoded(asn1encoding.der);
                }
                catch (exception e)
                {
                    throw new runtimeexception("error encoding " + e.tostring());
                }
            }
        }

        return null;
    }

    private set getextensionoids(
        boolean critical) 
    {
        extensions  extensions = cert.getacinfo().getextensions();

        if (extensions != null)
        {
            set             set = new hashset();
            enumeration     e = extensions.oids();

            while (e.hasmoreelements())
            {
                asn1objectidentifier oid = (asn1objectidentifier)e.nextelement();
                extension            ext = extensions.getextension(oid);

                if (ext.iscritical() == critical)
                {
                    set.add(oid.getid());
                }
            }

            return set;
        }

        return null;
    }
    
    public set getnoncriticalextensionoids() 
    {
        return getextensionoids(false);
    }

    public set getcriticalextensionoids() 
    {
        return getextensionoids(true);
    }
    
    public boolean hasunsupportedcriticalextension()
    {
        set  extensions = getcriticalextensionoids();

        return extensions != null && !extensions.isempty();
    }

    public x509attribute[] getattributes()
    {
        asn1sequence    seq = cert.getacinfo().getattributes();
        x509attribute[] attrs = new x509attribute[seq.size()];
        
        for (int i = 0; i != seq.size(); i++)
        {
            attrs[i] = new x509attribute((asn1encodable)seq.getobjectat(i));
        }
        
        return attrs;
    }
    
    public x509attribute[] getattributes(string oid)
    {
        asn1sequence    seq = cert.getacinfo().getattributes();
        list            list = new arraylist();
        
        for (int i = 0; i != seq.size(); i++)
        {
            x509attribute attr = new x509attribute((asn1encodable)seq.getobjectat(i));
            if (attr.getoid().equals(oid))
            {
                list.add(attr);
            }
        }
        
        if (list.size() == 0)
        {
            return null;
        }
        
        return (x509attribute[])list.toarray(new x509attribute[list.size()]);
    }

    public boolean equals(
        object o)
    {
        if (o == this)
        {
            return true;
        }

        if (!(o instanceof x509attributecertificate))
        {
            return false;
        }

        x509attributecertificate other = (x509attributecertificate)o;

        try
        {
            byte[] b1 = this.getencoded();
            byte[] b2 = other.getencoded();

            return arrays.areequal(b1, b2);
        }
        catch (ioexception e)
        {
            return false;
        }
    }

    public int hashcode()
    {
        try
        {
            return arrays.hashcode(this.getencoded());
        }
        catch (ioexception e)
        {
            return 0;
        }
    }
}
