package org.ripple.bouncycastle.jcajce.provider.asymmetric.dsa;

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
import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.pkcs.privatekeyinfo;
import org.ripple.bouncycastle.asn1.x509.algorithmidentifier;
import org.ripple.bouncycastle.asn1.x509.dsaparameter;
import org.ripple.bouncycastle.asn1.x9.x9objectidentifiers;
import org.ripple.bouncycastle.crypto.params.dsaprivatekeyparameters;
import org.ripple.bouncycastle.jcajce.provider.asymmetric.util.keyutil;
import org.ripple.bouncycastle.jcajce.provider.asymmetric.util.pkcs12bagattributecarrierimpl;
import org.ripple.bouncycastle.jce.interfaces.pkcs12bagattributecarrier;

public class bcdsaprivatekey
    implements dsaprivatekey, pkcs12bagattributecarrier
{
    private static final long serialversionuid = -4677259546958385734l;

    private biginteger          x;
    private transient dsaparams dsaspec;

    private transient pkcs12bagattributecarrierimpl attrcarrier = new pkcs12bagattributecarrierimpl();

    protected bcdsaprivatekey()
    {
    }

    bcdsaprivatekey(
        dsaprivatekey key)
    {
        this.x = key.getx();
        this.dsaspec = key.getparams();
    }

    bcdsaprivatekey(
        dsaprivatekeyspec spec)
    {
        this.x = spec.getx();
        this.dsaspec = new dsaparameterspec(spec.getp(), spec.getq(), spec.getg());
    }

    public bcdsaprivatekey(
        privatekeyinfo info)
        throws ioexception
    {
        dsaparameter    params = dsaparameter.getinstance(info.getprivatekeyalgorithm().getparameters());
        asn1integer      derx = (asn1integer)info.parseprivatekey();

        this.x = derx.getvalue();
        this.dsaspec = new dsaparameterspec(params.getp(), params.getq(), params.getg());
    }

    bcdsaprivatekey(
        dsaprivatekeyparameters params)
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
        return keyutil.getencodedprivatekeyinfo(new algorithmidentifier(x9objectidentifiers.id_dsa, new dsaparameter(dsaspec.getp(), dsaspec.getq(), dsaspec.getg()).toasn1primitive()), new asn1integer(getx()));
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
        in.defaultreadobject();

        this.dsaspec = new dsaparameterspec((biginteger)in.readobject(), (biginteger)in.readobject(), (biginteger)in.readobject());
        this.attrcarrier = new pkcs12bagattributecarrierimpl();
    }

    private void writeobject(
        objectoutputstream out)
        throws ioexception
    {
        out.defaultwriteobject();

        out.writeobject(dsaspec.getp());
        out.writeobject(dsaspec.getq());
        out.writeobject(dsaspec.getg());
    }
}
