package org.ripple.bouncycastle.jcajce.provider.asymmetric.dsa;

import java.io.ioexception;
import java.io.objectinputstream;
import java.io.objectoutputstream;
import java.math.biginteger;
import java.security.interfaces.dsaparams;
import java.security.interfaces.dsapublickey;
import java.security.spec.dsaparameterspec;
import java.security.spec.dsapublickeyspec;

import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.dernull;
import org.ripple.bouncycastle.asn1.x509.algorithmidentifier;
import org.ripple.bouncycastle.asn1.x509.dsaparameter;
import org.ripple.bouncycastle.asn1.x509.subjectpublickeyinfo;
import org.ripple.bouncycastle.asn1.x9.x9objectidentifiers;
import org.ripple.bouncycastle.crypto.params.dsapublickeyparameters;
import org.ripple.bouncycastle.jcajce.provider.asymmetric.util.keyutil;

public class bcdsapublickey
    implements dsapublickey
{
    private static final long serialversionuid = 1752452449903495175l;

    private biginteger      y;
    private transient dsaparams       dsaspec;

    bcdsapublickey(
        dsapublickeyspec spec)
    {
        this.y = spec.gety();
        this.dsaspec = new dsaparameterspec(spec.getp(), spec.getq(), spec.getg());
    }

    bcdsapublickey(
        dsapublickey key)
    {
        this.y = key.gety();
        this.dsaspec = key.getparams();
    }

    bcdsapublickey(
        dsapublickeyparameters params)
    {
        this.y = params.gety();
        this.dsaspec = new dsaparameterspec(params.getparameters().getp(), params.getparameters().getq(), params.getparameters().getg());
    }

    bcdsapublickey(
        biginteger y,
        dsaparameterspec dsaspec)
    {
        this.y = y;
        this.dsaspec = dsaspec;
    }

    public bcdsapublickey(
        subjectpublickeyinfo info)
    {

        asn1integer              dery;

        try
        {
            dery = (asn1integer)info.parsepublickey();
        }
        catch (ioexception e)
        {
            throw new illegalargumentexception("invalid info structure in dsa public key");
        }

        this.y = dery.getvalue();

        if (isnotnull(info.getalgorithm().getparameters()))
        {
            dsaparameter params = dsaparameter.getinstance(info.getalgorithm().getparameters());
            
            this.dsaspec = new dsaparameterspec(params.getp(), params.getq(), params.getg());
        }
    }

    private boolean isnotnull(asn1encodable parameters)
    {
        return parameters != null && !dernull.instance.equals(parameters.toasn1primitive());
    }

    public string getalgorithm()
    {
        return "dsa";
    }

    public string getformat()
    {
        return "x.509";
    }

    public byte[] getencoded()
    {
        if (dsaspec == null)
        {
            return keyutil.getencodedsubjectpublickeyinfo(new algorithmidentifier(x9objectidentifiers.id_dsa), new asn1integer(y));
        }

        return keyutil.getencodedsubjectpublickeyinfo(new algorithmidentifier(x9objectidentifiers.id_dsa, new dsaparameter(dsaspec.getp(), dsaspec.getq(), dsaspec.getg()).toasn1primitive()), new asn1integer(y));
    }

    public dsaparams getparams()
    {
        return dsaspec;
    }

    public biginteger gety()
    {
        return y;
    }

    public string tostring()
    {
        stringbuffer    buf = new stringbuffer();
        string          nl = system.getproperty("line.separator");

        buf.append("dsa public key").append(nl);
        buf.append("            y: ").append(this.gety().tostring(16)).append(nl);

        return buf.tostring();
    }

    public int hashcode()
    {
        return this.gety().hashcode() ^ this.getparams().getg().hashcode() 
                ^ this.getparams().getp().hashcode() ^ this.getparams().getq().hashcode();
    }

    public boolean equals(
        object o)
    {
        if (!(o instanceof dsapublickey))
        {
            return false;
        }
        
        dsapublickey other = (dsapublickey)o;
        
        return this.gety().equals(other.gety()) 
            && this.getparams().getg().equals(other.getparams().getg()) 
            && this.getparams().getp().equals(other.getparams().getp()) 
            && this.getparams().getq().equals(other.getparams().getq());
    }

    private void readobject(
        objectinputstream in)
        throws ioexception, classnotfoundexception
    {
        in.defaultreadobject();

        this.dsaspec = new dsaparameterspec((biginteger)in.readobject(), (biginteger)in.readobject(), (biginteger)in.readobject());
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
