package org.ripple.bouncycastle.jcajce.provider.asymmetric.elgamal;

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
import org.ripple.bouncycastle.asn1.derinteger;
import org.ripple.bouncycastle.asn1.oiw.elgamalparameter;
import org.ripple.bouncycastle.asn1.oiw.oiwobjectidentifiers;
import org.ripple.bouncycastle.asn1.pkcs.privatekeyinfo;
import org.ripple.bouncycastle.asn1.x509.algorithmidentifier;
import org.ripple.bouncycastle.crypto.params.elgamalprivatekeyparameters;
import org.ripple.bouncycastle.jcajce.provider.asymmetric.util.pkcs12bagattributecarrierimpl;
import org.ripple.bouncycastle.jce.interfaces.elgamalprivatekey;
import org.ripple.bouncycastle.jce.interfaces.pkcs12bagattributecarrier;
import org.ripple.bouncycastle.jce.spec.elgamalparameterspec;
import org.ripple.bouncycastle.jce.spec.elgamalprivatekeyspec;

public class bcelgamalprivatekey
    implements elgamalprivatekey, dhprivatekey, pkcs12bagattributecarrier
{
    static final long serialversionuid = 4819350091141529678l;
        
    private biginteger      x;

    private transient elgamalparameterspec   elspec;
    private transient pkcs12bagattributecarrierimpl attrcarrier = new pkcs12bagattributecarrierimpl();

    protected bcelgamalprivatekey()
    {
    }

    bcelgamalprivatekey(
        elgamalprivatekey key)
    {
        this.x = key.getx();
        this.elspec = key.getparameters();
    }

    bcelgamalprivatekey(
        dhprivatekey key)
    {
        this.x = key.getx();
        this.elspec = new elgamalparameterspec(key.getparams().getp(), key.getparams().getg());
    }
    
    bcelgamalprivatekey(
        elgamalprivatekeyspec spec)
    {
        this.x = spec.getx();
        this.elspec = new elgamalparameterspec(spec.getparams().getp(), spec.getparams().getg());
    }

    bcelgamalprivatekey(
        dhprivatekeyspec spec)
    {
        this.x = spec.getx();
        this.elspec = new elgamalparameterspec(spec.getp(), spec.getg());
    }
    
    bcelgamalprivatekey(
        privatekeyinfo info)
        throws ioexception
    {
        elgamalparameter     params = new elgamalparameter((asn1sequence)info.getalgorithmid().getparameters());
        derinteger      derx = asn1integer.getinstance(info.parseprivatekey());

        this.x = derx.getvalue();
        this.elspec = new elgamalparameterspec(params.getp(), params.getg());
    }

    bcelgamalprivatekey(
        elgamalprivatekeyparameters params)
    {
        this.x = params.getx();
        this.elspec = new elgamalparameterspec(params.getparameters().getp(), params.getparameters().getg());
    }

    public string getalgorithm()
    {
        return "elgamal";
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
            privatekeyinfo          info = new privatekeyinfo(new algorithmidentifier(oiwobjectidentifiers.elgamalalgorithm, new elgamalparameter(elspec.getp(), elspec.getg())), new derinteger(getx()));

            return info.getencoded(asn1encoding.der);
        }
        catch (ioexception e)
        {
            return null;
        }
    }

    public elgamalparameterspec getparameters()
    {
        return elspec;
    }

    public dhparameterspec getparams()
    {
        return new dhparameterspec(elspec.getp(), elspec.getg());
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

    private void readobject(
        objectinputstream   in)
        throws ioexception, classnotfoundexception
    {
        in.defaultreadobject();

        this.elspec = new elgamalparameterspec((biginteger)in.readobject(), (biginteger)in.readobject());
        this.attrcarrier = new pkcs12bagattributecarrierimpl();
    }

    private void writeobject(
        objectoutputstream  out)
        throws ioexception
    {
        out.defaultwriteobject();

        out.writeobject(elspec.getp());
        out.writeobject(elspec.getg());
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
}
