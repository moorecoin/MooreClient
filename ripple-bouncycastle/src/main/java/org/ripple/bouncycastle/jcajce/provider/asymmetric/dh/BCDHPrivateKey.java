package org.ripple.bouncycastle.jcajce.provider.asymmetric.dh;

import java.io.ioexception;
import java.io.objectinputstream;
import java.io.objectoutputstream;
import java.math.biginteger;
import java.util.enumeration;

import javax.crypto.interfaces.dhprivatekey;
import javax.crypto.spec.dhparameterspec;
import javax.crypto.spec.dhprivatekeyspec;

import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1encoding;
import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.pkcs.dhparameter;
import org.ripple.bouncycastle.asn1.pkcs.pkcsobjectidentifiers;
import org.ripple.bouncycastle.asn1.pkcs.privatekeyinfo;
import org.ripple.bouncycastle.asn1.x509.algorithmidentifier;
import org.ripple.bouncycastle.asn1.x9.dhdomainparameters;
import org.ripple.bouncycastle.asn1.x9.x9objectidentifiers;
import org.ripple.bouncycastle.crypto.params.dhprivatekeyparameters;
import org.ripple.bouncycastle.jcajce.provider.asymmetric.util.pkcs12bagattributecarrierimpl;
import org.ripple.bouncycastle.jce.interfaces.pkcs12bagattributecarrier;


public class bcdhprivatekey
    implements dhprivatekey, pkcs12bagattributecarrier
{
    static final long serialversionuid = 311058815616901812l;
    
    private biginteger      x;

    private transient dhparameterspec dhspec;
    private transient privatekeyinfo  info;

    private transient pkcs12bagattributecarrierimpl attrcarrier = new pkcs12bagattributecarrierimpl();

    protected bcdhprivatekey()
    {
    }

    bcdhprivatekey(
        dhprivatekey key)
    {
        this.x = key.getx();
        this.dhspec = key.getparams();
    }

    bcdhprivatekey(
        dhprivatekeyspec spec)
    {
        this.x = spec.getx();
        this.dhspec = new dhparameterspec(spec.getp(), spec.getg());
    }

    public bcdhprivatekey(
        privatekeyinfo info)
        throws ioexception
    {
        asn1sequence    seq = asn1sequence.getinstance(info.getprivatekeyalgorithm().getparameters());
        asn1integer      derx = (asn1integer)info.parseprivatekey();
        asn1objectidentifier id = info.getprivatekeyalgorithm().getalgorithm();

        this.info = info;
        this.x = derx.getvalue();

        if (id.equals(pkcsobjectidentifiers.dhkeyagreement))
        {
            dhparameter params = dhparameter.getinstance(seq);

            if (params.getl() != null)
            {
                this.dhspec = new dhparameterspec(params.getp(), params.getg(), params.getl().intvalue());
            }
            else
            {
                this.dhspec = new dhparameterspec(params.getp(), params.getg());
            }
        }
        else if (id.equals(x9objectidentifiers.dhpublicnumber))
        {
            dhdomainparameters params = dhdomainparameters.getinstance(seq);

            this.dhspec = new dhparameterspec(params.getp().getvalue(), params.getg().getvalue());
        }
        else
        {
            throw new illegalargumentexception("unknown algorithm type: " + id);
        }
    }

    bcdhprivatekey(
        dhprivatekeyparameters params)
    {
        this.x = params.getx();
        this.dhspec = new dhparameterspec(params.getparameters().getp(), params.getparameters().getg(), params.getparameters().getl());
    }

    public string getalgorithm()
    {
        return "dh";
    }

    /**
     * return the encoding format we produce in getencoded().
     *
     * @return the string "pkcs#8"
     */
    public string getformat()
    {
        return "pkcs#8";
    }

    /**
     * return a pkcs8 representation of the key. the sequence returned
     * represents a full privatekeyinfo object.
     *
     * @return a pkcs8 representation of the key.
     */
    public byte[] getencoded()
    {
        try
        {
            if (info != null)
            {
                return info.getencoded(asn1encoding.der);
            }

            privatekeyinfo          info = new privatekeyinfo(new algorithmidentifier(pkcsobjectidentifiers.dhkeyagreement, new dhparameter(dhspec.getp(), dhspec.getg(), dhspec.getl()).toasn1primitive()), new asn1integer(getx()));

            return info.getencoded(asn1encoding.der);
        }
        catch (exception e)
        {
            return null;
        }
    }

    public dhparameterspec getparams()
    {
        return dhspec;
    }

    public biginteger getx()
    {
        return x;
    }

    public boolean equals(
        object o)
    {
        if (!(o instanceof dhprivatekey))
        {
            return false;
        }

        dhprivatekey other = (dhprivatekey)o;

        return this.getx().equals(other.getx())
            && this.getparams().getg().equals(other.getparams().getg())
            && this.getparams().getp().equals(other.getparams().getp())
            && this.getparams().getl() == other.getparams().getl();
    }

    public int hashcode()
    {
        return this.getx().hashcode() ^ this.getparams().getg().hashcode()
                ^ this.getparams().getp().hashcode() ^ this.getparams().getl();
    }

    public void setbagattribute(
        asn1objectidentifier oid,
        asn1encodable attribute)
    {
        attrcarrier.setbagattribute(oid, attribute);
    }

    public asn1encodable getbagattribute(
        asn1objectidentifier oid)
    {
        return attrcarrier.getbagattribute(oid);
    }

    public enumeration getbagattributekeys()
    {
        return attrcarrier.getbagattributekeys();
    }

    private void readobject(
        objectinputstream   in)
        throws ioexception, classnotfoundexception
    {
        in.defaultreadobject();

        this.dhspec = new dhparameterspec((biginteger)in.readobject(), (biginteger)in.readobject(), in.readint());
        this.info = null;
        this.attrcarrier = new pkcs12bagattributecarrierimpl();
    }

    private void writeobject(
        objectoutputstream  out)
        throws ioexception
    {
        out.defaultwriteobject();

        out.writeobject(dhspec.getp());
        out.writeobject(dhspec.getg());
        out.writeint(dhspec.getl());
    }
}
