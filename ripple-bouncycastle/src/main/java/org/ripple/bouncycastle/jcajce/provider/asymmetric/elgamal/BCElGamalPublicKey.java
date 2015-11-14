package org.ripple.bouncycastle.jcajce.provider.asymmetric.elgamal;

import java.io.ioexception;
import java.io.objectinputstream;
import java.io.objectoutputstream;
import java.math.biginteger;

import javax.crypto.interfaces.dhpublickey;
import javax.crypto.spec.dhparameterspec;
import javax.crypto.spec.dhpublickeyspec;

import org.ripple.bouncycastle.asn1.asn1encoding;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.derinteger;
import org.ripple.bouncycastle.asn1.oiw.elgamalparameter;
import org.ripple.bouncycastle.asn1.oiw.oiwobjectidentifiers;
import org.ripple.bouncycastle.asn1.x509.algorithmidentifier;
import org.ripple.bouncycastle.asn1.x509.subjectpublickeyinfo;
import org.ripple.bouncycastle.crypto.params.elgamalpublickeyparameters;
import org.ripple.bouncycastle.jce.interfaces.elgamalpublickey;
import org.ripple.bouncycastle.jce.spec.elgamalparameterspec;
import org.ripple.bouncycastle.jce.spec.elgamalpublickeyspec;

public class bcelgamalpublickey
    implements elgamalpublickey, dhpublickey
{
    static final long serialversionuid = 8712728417091216948l;
        
    private biginteger              y;
    private transient elgamalparameterspec    elspec;

    bcelgamalpublickey(
        elgamalpublickeyspec spec)
    {
        this.y = spec.gety();
        this.elspec = new elgamalparameterspec(spec.getparams().getp(), spec.getparams().getg());
    }

    bcelgamalpublickey(
        dhpublickeyspec spec)
    {
        this.y = spec.gety();
        this.elspec = new elgamalparameterspec(spec.getp(), spec.getg());
    }
    
    bcelgamalpublickey(
        elgamalpublickey key)
    {
        this.y = key.gety();
        this.elspec = key.getparameters();
    }

    bcelgamalpublickey(
        dhpublickey key)
    {
        this.y = key.gety();
        this.elspec = new elgamalparameterspec(key.getparams().getp(), key.getparams().getg());
    }
    
    bcelgamalpublickey(
        elgamalpublickeyparameters params)
    {
        this.y = params.gety();
        this.elspec = new elgamalparameterspec(params.getparameters().getp(), params.getparameters().getg());
    }

    bcelgamalpublickey(
        biginteger y,
        elgamalparameterspec elspec)
    {
        this.y = y;
        this.elspec = elspec;
    }

    bcelgamalpublickey(
        subjectpublickeyinfo info)
    {
        elgamalparameter        params = new elgamalparameter((asn1sequence)info.getalgorithmid().getparameters());
        derinteger              dery = null;

        try
        {
            dery = (derinteger)info.parsepublickey();
        }
        catch (ioexception e)
        {
            throw new illegalargumentexception("invalid info structure in dsa public key");
        }

        this.y = dery.getvalue();
        this.elspec = new elgamalparameterspec(params.getp(), params.getg());
    }

    public string getalgorithm()
    {
        return "elgamal";
    }

    public string getformat()
    {
        return "x.509";
    }

    public byte[] getencoded()
    {
        try
        {
            subjectpublickeyinfo    info = new subjectpublickeyinfo(new algorithmidentifier(oiwobjectidentifiers.elgamalalgorithm, new elgamalparameter(elspec.getp(), elspec.getg())), new derinteger(y));

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

    public biginteger gety()
    {
        return y;
    }

    public int hashcode()
    {
        return this.gety().hashcode() ^ this.getparams().getg().hashcode()
                ^ this.getparams().getp().hashcode() ^ this.getparams().getl();
    }

    public boolean equals(
        object o)
    {
        if (!(o instanceof dhpublickey))
        {
            return false;
        }

        dhpublickey other = (dhpublickey)o;

        return this.gety().equals(other.gety())
            && this.getparams().getg().equals(other.getparams().getg())
            && this.getparams().getp().equals(other.getparams().getp())
            && this.getparams().getl() == other.getparams().getl();
    }

    private void readobject(
        objectinputstream   in)
        throws ioexception, classnotfoundexception
    {
        in.defaultreadobject();

        this.elspec = new elgamalparameterspec((biginteger)in.readobject(), (biginteger)in.readobject());
    }

    private void writeobject(
        objectoutputstream  out)
        throws ioexception
    {
        out.defaultwriteobject();

        out.writeobject(elspec.getp());
        out.writeobject(elspec.getg());
    }
}
