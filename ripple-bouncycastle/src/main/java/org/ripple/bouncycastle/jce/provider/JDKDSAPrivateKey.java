package org.ripple.bouncycastle.jce.provider;

import java.io.ioexception;
import java.io.objectinputstream;
import java.io.objectoutputstream;
import java.math.biginteger;
import java.security.interfaces.dsaparams;
import java.security.interfaces.dsaprivatekey;
import java.security.spec.dsaparameterspec;
import java.security.spec.dsaprivatekeyspec;
import java.util.enumeration;

import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1encoding;
import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.derinteger;
import org.ripple.bouncycastle.asn1.pkcs.privatekeyinfo;
import org.ripple.bouncycastle.asn1.x509.algorithmidentifier;
import org.ripple.bouncycastle.asn1.x509.dsaparameter;
import org.ripple.bouncycastle.asn1.x9.x9objectidentifiers;
import org.ripple.bouncycastle.crypto.params.dsaprivatekeyparameters;
import org.ripple.bouncycastle.jcajce.provider.asymmetric.util.pkcs12bagattributecarrierimpl;
import org.ripple.bouncycastle.jce.interfaces.pkcs12bagattributecarrier;

public class jdkdsaprivatekey
    implements dsaprivatekey, pkcs12bagattributecarrier
{
    private static final long serialversionuid = -4677259546958385734l;

    biginteger          x;
    dsaparams           dsaspec;

    private pkcs12bagattributecarrierimpl   attrcarrier = new pkcs12bagattributecarrierimpl();

    protected jdkdsaprivatekey()
    {
    }

    jdkdsaprivatekey(
        dsaprivatekey    key)
    {
        this.x = key.getx();
        this.dsaspec = key.getparams();
    }

    jdkdsaprivatekey(
        dsaprivatekeyspec    spec)
    {
        this.x = spec.getx();
        this.dsaspec = new dsaparameterspec(spec.getp(), spec.getq(), spec.getg());
    }

    jdkdsaprivatekey(
        privatekeyinfo  info)
        throws ioexception
    {
        dsaparameter    params = dsaparameter.getinstance(info.getprivatekeyalgorithm().getparameters());
        derinteger      derx = asn1integer.getinstance(info.parseprivatekey());

        this.x = derx.getvalue();
        this.dsaspec = new dsaparameterspec(params.getp(), params.getq(), params.getg());
    }

    jdkdsaprivatekey(
        dsaprivatekeyparameters  params)
    {
        this.x = params.getx();
        this.dsaspec = new dsaparameterspec(params.getparameters().getp(), params.getparameters().getq(), params.getparameters().getg());
    }

    public string getalgorithm()
    {
        return "dsa";
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
            privatekeyinfo          info = new privatekeyinfo(new algorithmidentifier(x9objectidentifiers.id_dsa, new dsaparameter(dsaspec.getp(), dsaspec.getq(), dsaspec.getg())), new derinteger(getx()));

            return info.getencoded(asn1encoding.der);
        }
        catch (ioexception e)
        {
            return null;
        }
    }

    public dsaparams getparams()
    {
        return dsaspec;
    }

    public biginteger getx()
    {
        return x;
    }

    public boolean equals(
        object o)
    {
        if (!(o instanceof dsaprivatekey))
        {
            return false;
        }
        
        dsaprivatekey other = (dsaprivatekey)o;
        
        return this.getx().equals(other.getx()) 
            && this.getparams().getg().equals(other.getparams().getg()) 
            && this.getparams().getp().equals(other.getparams().getp()) 
            && this.getparams().getq().equals(other.getparams().getq());
    }

    public int hashcode()
    {
        return this.getx().hashcode() ^ this.getparams().getg().hashcode()
                ^ this.getparams().getp().hashcode() ^ this.getparams().getq().hashcode();
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
        objectinputstream in)
        throws ioexception, classnotfoundexception
    {
        this.x = (biginteger)in.readobject();
        this.dsaspec = new dsaparameterspec((biginteger)in.readobject(), (biginteger)in.readobject(), (biginteger)in.readobject());
        this.attrcarrier = new pkcs12bagattributecarrierimpl();
        
        attrcarrier.readobject(in);
    }

    private void writeobject(
        objectoutputstream out)
        throws ioexception
    {
        out.writeobject(x);
        out.writeobject(dsaspec.getp());
        out.writeobject(dsaspec.getq());
        out.writeobject(dsaspec.getg());

        attrcarrier.writeobject(out);
    }
}
