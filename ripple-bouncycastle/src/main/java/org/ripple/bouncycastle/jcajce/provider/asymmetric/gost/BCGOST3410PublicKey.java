package org.ripple.bouncycastle.jcajce.provider.asymmetric.gost;

import java.io.ioexception;
import java.io.objectinputstream;
import java.io.objectoutputstream;
import java.math.biginteger;

import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.deroctetstring;
import org.ripple.bouncycastle.asn1.cryptopro.cryptoproobjectidentifiers;
import org.ripple.bouncycastle.asn1.cryptopro.gost3410publickeyalgparameters;
import org.ripple.bouncycastle.asn1.x509.algorithmidentifier;
import org.ripple.bouncycastle.asn1.x509.subjectpublickeyinfo;
import org.ripple.bouncycastle.crypto.params.gost3410publickeyparameters;
import org.ripple.bouncycastle.jcajce.provider.asymmetric.util.keyutil;
import org.ripple.bouncycastle.jce.interfaces.gost3410params;
import org.ripple.bouncycastle.jce.interfaces.gost3410publickey;
import org.ripple.bouncycastle.jce.spec.gost3410parameterspec;
import org.ripple.bouncycastle.jce.spec.gost3410publickeyparametersetspec;
import org.ripple.bouncycastle.jce.spec.gost3410publickeyspec;

public class bcgost3410publickey
    implements gost3410publickey
{
    static final long serialversionuid = -6251023343619275990l;

    private biginteger      y;
    private transient gost3410params  gost3410spec;

    bcgost3410publickey(
        gost3410publickeyspec spec)
    {
        this.y = spec.gety();
        this.gost3410spec = new gost3410parameterspec(new gost3410publickeyparametersetspec(spec.getp(), spec.getq(), spec.geta()));
    }

    bcgost3410publickey(
        gost3410publickey key)
    {
        this.y = key.gety();
        this.gost3410spec = key.getparameters();
    }

    bcgost3410publickey(
        gost3410publickeyparameters params,
        gost3410parameterspec spec)
    {
        this.y = params.gety();
        this.gost3410spec = spec;
    }

    bcgost3410publickey(
        biginteger y,
        gost3410parameterspec gost3410spec)
    {
        this.y = y;
        this.gost3410spec = gost3410spec;
    }

    bcgost3410publickey(
        subjectpublickeyinfo info)
    {
        gost3410publickeyalgparameters    params = new gost3410publickeyalgparameters((asn1sequence)info.getalgorithmid().getparameters());
        deroctetstring                    dery;

        try
        {
            dery = (deroctetstring)info.parsepublickey();
            
            byte[]                  keyenc = dery.getoctets();
            byte[]                  keybytes = new byte[keyenc.length];
            
            for (int i = 0; i != keyenc.length; i++)
            {
                keybytes[i] = keyenc[keyenc.length - 1 - i]; // was little endian
            }

            this.y = new biginteger(1, keybytes);
        }
        catch (ioexception e)
        {
            throw new illegalargumentexception("invalid info structure in gost3410 public key");
        }

        this.gost3410spec = gost3410parameterspec.frompublickeyalg(params);
    }

    public string getalgorithm()
    {
        return "gost3410";
    }

    public string getformat()
    {
        return "x.509";
    }

    public byte[] getencoded()
    {
        subjectpublickeyinfo    info;
        byte[]                  keyenc = this.gety().tobytearray();
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
                if (gost3410spec.getencryptionparamsetoid() != null)
                {
                    info = new subjectpublickeyinfo(new algorithmidentifier(cryptoproobjectidentifiers.gostr3410_94, new gost3410publickeyalgparameters(new asn1objectidentifier(gost3410spec.getpublickeyparamsetoid()), new asn1objectidentifier(gost3410spec.getdigestparamsetoid()), new asn1objectidentifier(gost3410spec.getencryptionparamsetoid()))), new deroctetstring(keybytes));
                }
                else
                {
                    info = new subjectpublickeyinfo(new algorithmidentifier(cryptoproobjectidentifiers.gostr3410_94, new gost3410publickeyalgparameters(new asn1objectidentifier(gost3410spec.getpublickeyparamsetoid()), new asn1objectidentifier(gost3410spec.getdigestparamsetoid()))), new deroctetstring(keybytes));
                }
            }
            else
            {
                info = new subjectpublickeyinfo(new algorithmidentifier(cryptoproobjectidentifiers.gostr3410_94), new deroctetstring(keybytes));
            }

            return keyutil.getencodedsubjectpublickeyinfo(info);
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

    public biginteger gety()
    {
        return y;
    }

    public string tostring()
    {
        stringbuffer    buf = new stringbuffer();
        string          nl = system.getproperty("line.separator");

        buf.append("gost3410 public key").append(nl);
        buf.append("            y: ").append(this.gety().tostring(16)).append(nl);

        return buf.tostring();
    }
    
    public boolean equals(object o)
    {
        if (o instanceof bcgost3410publickey)
        {
            bcgost3410publickey other = (bcgost3410publickey)o;
            
            return this.y.equals(other.y) && this.gost3410spec.equals(other.gost3410spec);
        }
        
        return false;
    }
    
    public int hashcode()
    {
        return y.hashcode() ^ gost3410spec.hashcode();
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
