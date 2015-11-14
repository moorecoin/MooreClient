package org.ripple.bouncycastle.jcajce.provider.asymmetric.dh;

import java.io.ioexception;
import java.io.objectinputstream;
import java.io.objectoutputstream;
import java.math.biginteger;

import javax.crypto.interfaces.dhpublickey;
import javax.crypto.spec.dhparameterspec;
import javax.crypto.spec.dhpublickeyspec;

import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.pkcs.dhparameter;
import org.ripple.bouncycastle.asn1.pkcs.pkcsobjectidentifiers;
import org.ripple.bouncycastle.asn1.x509.algorithmidentifier;
import org.ripple.bouncycastle.asn1.x509.subjectpublickeyinfo;
import org.ripple.bouncycastle.asn1.x9.dhdomainparameters;
import org.ripple.bouncycastle.asn1.x9.x9objectidentifiers;
import org.ripple.bouncycastle.crypto.params.dhpublickeyparameters;
import org.ripple.bouncycastle.jcajce.provider.asymmetric.util.keyutil;

public class bcdhpublickey
    implements dhpublickey
{
    static final long serialversionuid = -216691575254424324l;
    
    private biginteger              y;

    private transient dhparameterspec         dhspec;
    private transient subjectpublickeyinfo    info;
    
    bcdhpublickey(
        dhpublickeyspec spec)
    {
        this.y = spec.gety();
        this.dhspec = new dhparameterspec(spec.getp(), spec.getg());
    }

    bcdhpublickey(
        dhpublickey key)
    {
        this.y = key.gety();
        this.dhspec = key.getparams();
    }

    bcdhpublickey(
        dhpublickeyparameters params)
    {
        this.y = params.gety();
        this.dhspec = new dhparameterspec(params.getparameters().getp(), params.getparameters().getg(), params.getparameters().getl());
    }

    bcdhpublickey(
        biginteger y,
        dhparameterspec dhspec)
    {
        this.y = y;
        this.dhspec = dhspec;
    }

    public bcdhpublickey(
        subjectpublickeyinfo info)
    {
        this.info = info;

        asn1integer              dery;
        try
        {
            dery = (asn1integer)info.parsepublickey();
        }
        catch (ioexception e)
        {
            throw new illegalargumentexception("invalid info structure in dh public key");
        }

        this.y = dery.getvalue();

        asn1sequence seq = asn1sequence.getinstance(info.getalgorithm().getparameters());
        asn1objectidentifier id = info.getalgorithm().getalgorithm();

        // we need the pkcs check to handle older keys marked with the x9 oid.
        if (id.equals(pkcsobjectidentifiers.dhkeyagreement) || ispkcsparam(seq))
        {
            dhparameter             params = dhparameter.getinstance(seq);

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

    public string getalgorithm()
    {
        return "dh";
    }

    public string getformat()
    {
        return "x.509";
    }

    public byte[] getencoded()
    {
        if (info != null)
        {
            return keyutil.getencodedsubjectpublickeyinfo(info);
        }

        return keyutil.getencodedsubjectpublickeyinfo(new algorithmidentifier(pkcsobjectidentifiers.dhkeyagreement, new dhparameter(dhspec.getp(), dhspec.getg(), dhspec.getl()).toasn1primitive()), new asn1integer(y));
    }

    public dhparameterspec getparams()
    {
        return dhspec;
    }

    public biginteger gety()
    {
        return y;
    }

    private boolean ispkcsparam(asn1sequence seq)
    {
        if (seq.size() == 2)
        {
            return true;
        }
        
        if (seq.size() > 3)
        {
            return false;
        }

        asn1integer l = asn1integer.getinstance(seq.getobjectat(2));
        asn1integer p = asn1integer.getinstance(seq.getobjectat(0));

        if (l.getvalue().compareto(biginteger.valueof(p.getvalue().bitlength())) > 0)
        {
            return false;
        }

        return true;
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

        this.dhspec = new dhparameterspec((biginteger)in.readobject(), (biginteger)in.readobject(), in.readint());
        this.info = null;
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
