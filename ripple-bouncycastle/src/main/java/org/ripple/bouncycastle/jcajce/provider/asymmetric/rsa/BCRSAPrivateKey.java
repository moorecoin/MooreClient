package org.ripple.bouncycastle.jcajce.provider.asymmetric.rsa;

import java.io.ioexception;
import java.io.objectinputstream;
import java.io.objectoutputstream;
import java.math.biginteger;
import java.security.interfaces.rsaprivatekey;
import java.security.spec.rsaprivatekeyspec;
import java.util.enumeration;

import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.dernull;
import org.ripple.bouncycastle.asn1.pkcs.pkcsobjectidentifiers;
import org.ripple.bouncycastle.asn1.x509.algorithmidentifier;
import org.ripple.bouncycastle.crypto.params.rsakeyparameters;
import org.ripple.bouncycastle.jcajce.provider.asymmetric.util.keyutil;
import org.ripple.bouncycastle.jcajce.provider.asymmetric.util.pkcs12bagattributecarrierimpl;
import org.ripple.bouncycastle.jce.interfaces.pkcs12bagattributecarrier;

public class bcrsaprivatekey
    implements rsaprivatekey, pkcs12bagattributecarrier
{
    static final long serialversionuid = 5110188922551353628l;

    private static biginteger zero = biginteger.valueof(0);

    protected biginteger modulus;
    protected biginteger privateexponent;

    private transient pkcs12bagattributecarrierimpl   attrcarrier = new pkcs12bagattributecarrierimpl();

    protected bcrsaprivatekey()
    {
    }

    bcrsaprivatekey(
        rsakeyparameters key)
    {
        this.modulus = key.getmodulus();
        this.privateexponent = key.getexponent();
    }

    bcrsaprivatekey(
        rsaprivatekeyspec spec)
    {
        this.modulus = spec.getmodulus();
        this.privateexponent = spec.getprivateexponent();
    }

    bcrsaprivatekey(
        rsaprivatekey key)
    {
        this.modulus = key.getmodulus();
        this.privateexponent = key.getprivateexponent();
    }

    public biginteger getmodulus()
    {
        return modulus;
    }

    public biginteger getprivateexponent()
    {
        return privateexponent;
    }

    public string getalgorithm()
    {
        return "rsa";
    }

    public string getformat()
    {
        return "pkcs#8";
    }

    public byte[] getencoded()
    {
        return keyutil.getencodedprivatekeyinfo(new algorithmidentifier(pkcsobjectidentifiers.rsaencryption, dernull.instance), new org.ripple.bouncycastle.asn1.pkcs.rsaprivatekey(getmodulus(), zero, getprivateexponent(), zero, zero, zero, zero, zero));
    }

    public boolean equals(object o)
    {
        if (!(o instanceof rsaprivatekey))
        {
            return false;
        }

        if (o == this)
        {
            return true;
        }

        rsaprivatekey key = (rsaprivatekey)o;

        return getmodulus().equals(key.getmodulus())
            && getprivateexponent().equals(key.getprivateexponent());
    }

    public int hashcode()
    {
        return getmodulus().hashcode() ^ getprivateexponent().hashcode();
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

        this.attrcarrier = new pkcs12bagattributecarrierimpl();
    }

    private void writeobject(
        objectoutputstream  out)
        throws ioexception
    {
        out.defaultwriteobject();
    }
}
