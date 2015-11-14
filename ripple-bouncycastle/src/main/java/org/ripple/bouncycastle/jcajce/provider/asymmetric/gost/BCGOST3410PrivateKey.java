package org.ripple.bouncycastle.jcajce.provider.asymmetric.gost;

import java.io.ioexception;
import java.io.objectinputstream;
import java.io.objectoutputstream;
import java.math.biginteger;
import java.util.enumeration;

import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1encoding;
import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.asn1octetstring;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.deroctetstring;
import org.ripple.bouncycastle.asn1.cryptopro.cryptoproobjectidentifiers;
import org.ripple.bouncycastle.asn1.cryptopro.gost3410publickeyalgparameters;
import org.ripple.bouncycastle.asn1.pkcs.privatekeyinfo;
import org.ripple.bouncycastle.asn1.x509.algorithmidentifier;
import org.ripple.bouncycastle.crypto.params.gost3410privatekeyparameters;
import org.ripple.bouncycastle.jcajce.provider.asymmetric.util.pkcs12bagattributecarrierimpl;
import org.ripple.bouncycastle.jce.interfaces.gost3410params;
import org.ripple.bouncycastle.jce.interfaces.gost3410privatekey;
import org.ripple.bouncycastle.jce.interfaces.pkcs12bagattributecarrier;
import org.ripple.bouncycastle.jce.spec.gost3410parameterspec;
import org.ripple.bouncycastle.jce.spec.gost3410privatekeyspec;
import org.ripple.bouncycastle.jce.spec.gost3410publickeyparametersetspec;

public class bcgost3410privatekey
    implements gost3410privatekey, pkcs12bagattributecarrier
{
    static final long serialversionuid = 8581661527592305464l;

    private biginteger          x;

    private transient   gost3410params      gost3410spec;
    private transient   pkcs12bagattributecarrier attrcarrier = new pkcs12bagattributecarrierimpl();

    protected bcgost3410privatekey()
    {
    }

    bcgost3410privatekey(
        gost3410privatekey key)
    {
        this.x = key.getx();
        this.gost3410spec = key.getparameters();
    }

    bcgost3410privatekey(
        gost3410privatekeyspec spec)
    {
        this.x = spec.getx();
        this.gost3410spec = new gost3410parameterspec(new gost3410publickeyparametersetspec(spec.getp(), spec.getq(), spec.geta()));
    }

    bcgost3410privatekey(
        privatekeyinfo info)
        throws ioexception
    {
        gost3410publickeyalgparameters    params = new gost3410publickeyalgparameters((asn1sequence)info.getalgorithmid().getparameters());
        asn1octetstring      derx = asn1octetstring.getinstance(info.parseprivatekey());
        byte[]              keyenc = derx.getoctets();
        byte[]              keybytes = new byte[keyenc.length];
        
        for (int i = 0; i != keyenc.length; i++)
        {
            keybytes[i] = keyenc[keyenc.length - 1 - i]; // was little endian
        }
        
        this.x = new biginteger(1, keybytes);
        this.gost3410spec = gost3410parameterspec.frompublickeyalg(params);
    }

    bcgost3410privatekey(
        gost3410privatekeyparameters params,
        gost3410parameterspec spec)
    {
        this.x = params.getx();
        this.gost3410spec = spec;

        if (spec == null) 
        {
            throw new illegalargumentexception("spec is null");
        }
    }

    public string getalgorithm()
    {
        return "gost3410";
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
        privatekeyinfo          info;
        byte[]                  keyenc = this.getx().tobytearray();
        byte[]                  keybytes;

        if (keyenc[0] == 0)
        {
            keybytes = new byte[keyenc.length - 1];
        }
        else
        {
            keybytes = new byte[keyenc.length];
        }
        
        for (int i = 0; i != keybytes.length; i++)
        {
            keybytes[i] = keyenc[keyenc.length - 1 - i]; // must be little endian
        }

        try
        {
            if (gost3410spec instanceof gost3410parameterspec)
            {
                info = new privatekeyinfo(new algorithmidentifier(cryptoproobjectidentifiers.gostr3410_94, new gost3410publickeyalgparameters(new asn1objectidentifier(gost3410spec.getpublickeyparamsetoid()), new asn1objectidentifier(gost3410spec.getdigestparamsetoid()))), new deroctetstring(keybytes));
            }
            else
            {
                info = new privatekeyinfo(new algorithmidentifier(cryptoproobjectidentifiers.gostr3410_94), new deroctetstring(keybytes));
            }

            return info.getencoded(asn1encoding.der);
        }
        catch (ioexception e)
        {
            return null;
        }
    }

    public gost3410params getparameters()
    {
        return gost3410spec;
    }

    public biginteger getx()
    {
        return x;
    }

    public boolean equals(
        object o)
    {
        if (!(o instanceof gost3410privatekey))
        {
            return false;
        }

        gost3410privatekey other = (gost3410privatekey)o;

        return this.getx().equals(other.getx())
            && this.getparameters().getpublickeyparameters().equals(other.getparameters().getpublickeyparameters())
            && this.getparameters().getdigestparamsetoid().equals(other.getparameters().getdigestparamsetoid())
            && compareobj(this.getparameters().getencryptionparamsetoid(), other.getparameters().getencryptionparamsetoid());
    }

    private boolean compareobj(object o1, object o2)
    {
        if (o1 == o2)
        {
            return true;
        }

        if (o1 == null)
        {
            return false;
        }

        return o1.equals(o2);
    }

    public int hashcode()
    {
        return this.getx().hashcode() ^ gost3410spec.hashcode();
    }

    public void setbagattribute(
        asn1objectidentifier oid,
        asn1encodable        attribute)
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

        string publickeyparamsetoid = (string)in.readobject();
        if (publickeyparamsetoid != null)
        {
            this.gost3410spec = new gost3410parameterspec(publickeyparamsetoid, (string)in.readobject(), (string)in.readobject());
        }
        else
        {
            this.gost3410spec = new gost3410parameterspec(new gost3410publickeyparametersetspec((biginteger)in.readobject(), (biginteger)in.readobject(), (biginteger)in.readobject()));
            in.readobject();
            in.readobject();
        }
        this.attrcarrier = new pkcs12bagattributecarrierimpl();
    }

    private void writeobject(
        objectoutputstream out)
        throws ioexception
    {
        out.defaultwriteobject();

        if (gost3410spec.getpublickeyparamsetoid() != null)
        {
            out.writeobject(gost3410spec.getpublickeyparamsetoid());
            out.writeobject(gost3410spec.getdigestparamsetoid());
            out.writeobject(gost3410spec.getencryptionparamsetoid());
        }
        else
        {
            out.writeobject(null);
            out.writeobject(gost3410spec.getpublickeyparameters().getp());
            out.writeobject(gost3410spec.getpublickeyparameters().getq());
            out.writeobject(gost3410spec.getpublickeyparameters().geta());
            out.writeobject(gost3410spec.getdigestparamsetoid());
            out.writeobject(gost3410spec.getencryptionparamsetoid());
        }
    }
}
