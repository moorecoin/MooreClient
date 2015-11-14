package org.ripple.bouncycastle.jcajce.provider.asymmetric.rsa;

import java.io.ioexception;
import java.math.biginteger;
import java.security.interfaces.rsapublickey;
import java.security.spec.rsapublickeyspec;

import org.ripple.bouncycastle.asn1.dernull;
import org.ripple.bouncycastle.asn1.pkcs.pkcsobjectidentifiers;
import org.ripple.bouncycastle.asn1.x509.algorithmidentifier;
import org.ripple.bouncycastle.asn1.x509.subjectpublickeyinfo;
import org.ripple.bouncycastle.crypto.params.rsakeyparameters;
import org.ripple.bouncycastle.jcajce.provider.asymmetric.util.keyutil;

public class bcrsapublickey
    implements rsapublickey
{
    static final long serialversionuid = 2675817738516720772l;
    
    private biginteger modulus;
    private biginteger publicexponent;

    bcrsapublickey(
        rsakeyparameters key)
    {
        this.modulus = key.getmodulus();
        this.publicexponent = key.getexponent();
    }

    bcrsapublickey(
        rsapublickeyspec spec)
    {
        this.modulus = spec.getmodulus();
        this.publicexponent = spec.getpublicexponent();
    }

    bcrsapublickey(
        rsapublickey key)
    {
        this.modulus = key.getmodulus();
        this.publicexponent = key.getpublicexponent();
    }

    bcrsapublickey(
        subjectpublickeyinfo info)
    {
        try
        {
            org.ripple.bouncycastle.asn1.pkcs.rsapublickey  pubkey = org.ripple.bouncycastle.asn1.pkcs.rsapublickey.getinstance(info.parsepublickey());

            this.modulus = pubkey.getmodulus();
            this.publicexponent = pubkey.getpublicexponent();
        }
        catch (ioexception e)
        {
            throw new illegalargumentexception("invalid info structure in rsa public key");
        }
    }

    /**
     * return the modulus.
     *
     * @return the modulus.
     */
    public biginteger getmodulus()
    {
        return modulus;
    }

    /**
     * return the public exponent.
     *
     * @return the public exponent.
     */
    public biginteger getpublicexponent()
    {
        return publicexponent;
    }

    public string getalgorithm()
    {
        return "rsa";
    }

    public string getformat()
    {
        return "x.509";
    }

    public byte[] getencoded()
    {
        return keyutil.getencodedsubjectpublickeyinfo(new algorithmidentifier(pkcsobjectidentifiers.rsaencryption, dernull.instance), new org.ripple.bouncycastle.asn1.pkcs.rsapublickey(getmodulus(), getpublicexponent()));
    }

    public int hashcode()
    {
        return this.getmodulus().hashcode() ^ this.getpublicexponent().hashcode();
    }

    public boolean equals(object o)
    {
        if (o == this)
        {
            return true;
        }

        if (!(o instanceof rsapublickey))
        {
            return false;
        }

        rsapublickey key = (rsapublickey)o;

        return getmodulus().equals(key.getmodulus())
            && getpublicexponent().equals(key.getpublicexponent());
    }

    public string tostring()
    {
        stringbuffer    buf = new stringbuffer();
        string          nl = system.getproperty("line.separator");

        buf.append("rsa public key").append(nl);
        buf.append("            modulus: ").append(this.getmodulus().tostring(16)).append(nl);
        buf.append("    public exponent: ").append(this.getpublicexponent().tostring(16)).append(nl);

        return buf.tostring();
    }
}
