package org.ripple.bouncycastle.jcajce.provider.asymmetric.ec;

import java.io.ioexception;
import java.io.objectinputstream;
import java.io.objectoutputstream;
import java.math.biginteger;
import java.security.interfaces.ecpublickey;
import java.security.spec.ecparameterspec;
import java.security.spec.ecpoint;
import java.security.spec.ecpublickeyspec;
import java.security.spec.ellipticcurve;

import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.asn1octetstring;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.derbitstring;
import org.ripple.bouncycastle.asn1.dernull;
import org.ripple.bouncycastle.asn1.deroctetstring;
import org.ripple.bouncycastle.asn1.x509.algorithmidentifier;
import org.ripple.bouncycastle.asn1.x509.subjectpublickeyinfo;
import org.ripple.bouncycastle.asn1.x9.x962parameters;
import org.ripple.bouncycastle.asn1.x9.x9ecparameters;
import org.ripple.bouncycastle.asn1.x9.x9ecpoint;
import org.ripple.bouncycastle.asn1.x9.x9integerconverter;
import org.ripple.bouncycastle.asn1.x9.x9objectidentifiers;
import org.ripple.bouncycastle.crypto.params.ecdomainparameters;
import org.ripple.bouncycastle.crypto.params.ecpublickeyparameters;
import org.ripple.bouncycastle.jcajce.provider.asymmetric.util.ec5util;
import org.ripple.bouncycastle.jcajce.provider.asymmetric.util.ecutil;
import org.ripple.bouncycastle.jcajce.provider.asymmetric.util.keyutil;
import org.ripple.bouncycastle.jcajce.provider.config.providerconfiguration;
import org.ripple.bouncycastle.jce.interfaces.ecpointencoder;
import org.ripple.bouncycastle.jce.provider.bouncycastleprovider;
import org.ripple.bouncycastle.jce.spec.ecnamedcurvespec;
import org.ripple.bouncycastle.math.ec.eccurve;

public class bcecpublickey
    implements ecpublickey, org.ripple.bouncycastle.jce.interfaces.ecpublickey, ecpointencoder
{
    static final long serialversionuid = 2422789860422731812l;

    private string    algorithm = "ec";
    private boolean   withcompression;

    private transient org.ripple.bouncycastle.math.ec.ecpoint q;
    private transient ecparameterspec         ecspec;
    private transient providerconfiguration   configuration;

    public bcecpublickey(
        string algorithm,
        bcecpublickey key)
    {
        this.algorithm = algorithm;
        this.q = key.q;
        this.ecspec = key.ecspec;
        this.withcompression = key.withcompression;
        this.configuration = key.configuration;
    }
    
    public bcecpublickey(
        string algorithm,
        ecpublickeyspec spec,
        providerconfiguration configuration)
    {
        this.algorithm = algorithm;
        this.ecspec = spec.getparams();
        this.q = ec5util.convertpoint(ecspec, spec.getw(), false);
        this.configuration = configuration;
    }

    public bcecpublickey(
        string algorithm,
        org.ripple.bouncycastle.jce.spec.ecpublickeyspec spec,
        providerconfiguration configuration)
    {
        this.algorithm = algorithm;
        this.q = spec.getq();

        if (spec.getparams() != null) // can be null if implictlyca
        {
            eccurve curve = spec.getparams().getcurve();
            ellipticcurve ellipticcurve = ec5util.convertcurve(curve, spec.getparams().getseed());

            this.ecspec = ec5util.convertspec(ellipticcurve, spec.getparams());
        }
        else
        {
            if (q.getcurve() == null)
            {
                org.ripple.bouncycastle.jce.spec.ecparameterspec s = configuration.getecimplicitlyca();

                q = s.getcurve().createpoint(q.getx().tobiginteger(), q.gety().tobiginteger(), false);
            }               
            this.ecspec = null;
        }

        this.configuration = configuration;
    }
    
    public bcecpublickey(
        string algorithm,
        ecpublickeyparameters params,
        ecparameterspec spec,
        providerconfiguration configuration)
    {
        ecdomainparameters      dp = params.getparameters();

        this.algorithm = algorithm;
        this.q = params.getq();

        if (spec == null)
        {
            ellipticcurve ellipticcurve = ec5util.convertcurve(dp.getcurve(), dp.getseed());

            this.ecspec = createspec(ellipticcurve, dp);
        }
        else
        {
            this.ecspec = spec;
        }

        this.configuration = configuration;
    }

    public bcecpublickey(
        string algorithm,
        ecpublickeyparameters params,
        org.ripple.bouncycastle.jce.spec.ecparameterspec spec,
        providerconfiguration configuration)
    {
        ecdomainparameters      dp = params.getparameters();

        this.algorithm = algorithm;
        this.q = params.getq();

        if (spec == null)
        {
            ellipticcurve ellipticcurve = ec5util.convertcurve(dp.getcurve(), dp.getseed());

            this.ecspec = createspec(ellipticcurve, dp);
        }
        else
        {
            ellipticcurve ellipticcurve = ec5util.convertcurve(spec.getcurve(), spec.getseed());

            this.ecspec = ec5util.convertspec(ellipticcurve, spec);
        }

        this.configuration = configuration;
    }

    /*
     * called for implicitca
     */
    public bcecpublickey(
        string algorithm,
        ecpublickeyparameters params,
        providerconfiguration configuration)
    {
        this.algorithm = algorithm;
        this.q = params.getq();
        this.ecspec = null;
        this.configuration = configuration;
    }

    public bcecpublickey(
        ecpublickey key,
        providerconfiguration configuration)
    {
        this.algorithm = key.getalgorithm();
        this.ecspec = key.getparams();
        this.q = ec5util.convertpoint(this.ecspec, key.getw(), false);
    }

    bcecpublickey(
        string algorithm,
        subjectpublickeyinfo info,
        providerconfiguration configuration)
    {
        this.algorithm = algorithm;
        this.configuration = configuration;
        populatefrompubkeyinfo(info);
    }

    private ecparameterspec createspec(ellipticcurve ellipticcurve, ecdomainparameters dp)
    {
        return new ecparameterspec(
                ellipticcurve,
                new ecpoint(
                        dp.getg().getx().tobiginteger(),
                        dp.getg().gety().tobiginteger()),
                        dp.getn(),
                        dp.geth().intvalue());
    }

    private void populatefrompubkeyinfo(subjectpublickeyinfo info)
    {
        x962parameters params = new x962parameters((asn1primitive)info.getalgorithm().getparameters());
        eccurve                 curve;
        ellipticcurve           ellipticcurve;

        if (params.isnamedcurve())
        {
            asn1objectidentifier oid = (asn1objectidentifier)params.getparameters();
            x9ecparameters ecp = ecutil.getnamedcurvebyoid(oid);

            curve = ecp.getcurve();
            ellipticcurve = ec5util.convertcurve(curve, ecp.getseed());

            ecspec = new ecnamedcurvespec(
                    ecutil.getcurvename(oid),
                    ellipticcurve,
                    new ecpoint(
                            ecp.getg().getx().tobiginteger(),
                            ecp.getg().gety().tobiginteger()),
                    ecp.getn(),
                    ecp.geth());
        }
        else if (params.isimplicitlyca())
        {
            ecspec = null;
            curve = configuration.getecimplicitlyca().getcurve();
        }
        else
        {
            x9ecparameters          ecp = x9ecparameters.getinstance(params.getparameters());

            curve = ecp.getcurve();
            ellipticcurve = ec5util.convertcurve(curve, ecp.getseed());

            this.ecspec = new ecparameterspec(
                    ellipticcurve,
                    new ecpoint(
                            ecp.getg().getx().tobiginteger(),
                            ecp.getg().gety().tobiginteger()),
                    ecp.getn(),
                    ecp.geth().intvalue());
        }

        derbitstring    bits = info.getpublickeydata();
        byte[]          data = bits.getbytes();
        asn1octetstring key = new deroctetstring(data);

        //
        // extra octet string - one of our old certs...
        //
        if (data[0] == 0x04 && data[1] == data.length - 2
            && (data[2] == 0x02 || data[2] == 0x03))
        {
            int qlength = new x9integerconverter().getbytelength(curve);

            if (qlength >= data.length - 3)
            {
                try
                {
                    key = (asn1octetstring) asn1primitive.frombytearray(data);
                }
                catch (ioexception ex)
                {
                    throw new illegalargumentexception("error recovering public key");
                }
            }
        }
        x9ecpoint derq = new x9ecpoint(curve, key);

        this.q = derq.getpoint();
    }

    public string getalgorithm()
    {
        return algorithm;
    }

    public string getformat()
    {
        return "x.509";
    }

    public byte[] getencoded()
    {
        asn1encodable        params;
        subjectpublickeyinfo info;

        if (ecspec instanceof ecnamedcurvespec)
        {
            asn1objectidentifier curveoid = ecutil.getnamedcurveoid(((ecnamedcurvespec)ecspec).getname());
            if (curveoid == null)
            {
                curveoid = new asn1objectidentifier(((ecnamedcurvespec)ecspec).getname());
            }
            params = new x962parameters(curveoid);
        }
        else if (ecspec == null)
        {
            params = new x962parameters(dernull.instance);
        }
        else
        {
            eccurve curve = ec5util.convertcurve(ecspec.getcurve());

            x9ecparameters ecp = new x9ecparameters(
                curve,
                ec5util.convertpoint(curve, ecspec.getgenerator(), withcompression),
                ecspec.getorder(),
                biginteger.valueof(ecspec.getcofactor()),
                ecspec.getcurve().getseed());

            params = new x962parameters(ecp);
        }

        eccurve curve = this.enginegetq().getcurve();
        asn1octetstring p = (asn1octetstring)
            new x9ecpoint(curve.createpoint(this.getq().getx().tobiginteger(), this.getq().gety().tobiginteger(), withcompression)).toasn1primitive();

        info = new subjectpublickeyinfo(new algorithmidentifier(x9objectidentifiers.id_ecpublickey, params), p.getoctets());

        return keyutil.getencodedsubjectpublickeyinfo(info);
    }

    private void extractbytes(byte[] enckey, int offset, biginteger bi)
    {
        byte[] val = bi.tobytearray();
        if (val.length < 32)
        {
            byte[] tmp = new byte[32];
            system.arraycopy(val, 0, tmp, tmp.length - val.length, val.length);
            val = tmp;
        }

        for (int i = 0; i != 32; i++)
        {
            enckey[offset + i] = val[val.length - 1 - i];
        }
    }

    public ecparameterspec getparams()
    {
        return ecspec;
    }

    public org.ripple.bouncycastle.jce.spec.ecparameterspec getparameters()
    {
        if (ecspec == null)     // implictlyca
        {
            return null;
        }

        return ec5util.convertspec(ecspec, withcompression);
    }

    public ecpoint getw()
    {
        return new ecpoint(q.getx().tobiginteger(), q.gety().tobiginteger());
    }

    public org.ripple.bouncycastle.math.ec.ecpoint getq()
    {
        if (ecspec == null)
        {
            if (q instanceof org.ripple.bouncycastle.math.ec.ecpoint.fp)
            {
                return new org.ripple.bouncycastle.math.ec.ecpoint.fp(null, q.getx(), q.gety());
            }
            else
            {
                return new org.ripple.bouncycastle.math.ec.ecpoint.f2m(null, q.getx(), q.gety());
            }
        }

        return q;
    }

    public org.ripple.bouncycastle.math.ec.ecpoint enginegetq()
    {
        return q;
    }

    org.ripple.bouncycastle.jce.spec.ecparameterspec enginegetspec()
    {
        if (ecspec != null)
        {
            return ec5util.convertspec(ecspec, withcompression);
        }

        return configuration.getecimplicitlyca();
    }

    public string tostring()
    {
        stringbuffer    buf = new stringbuffer();
        string          nl = system.getproperty("line.separator");

        buf.append("ec public key").append(nl);
        buf.append("            x: ").append(this.q.getx().tobiginteger().tostring(16)).append(nl);
        buf.append("            y: ").append(this.q.gety().tobiginteger().tostring(16)).append(nl);

        return buf.tostring();

    }
    
    public void setpointformat(string style)
    {
       withcompression = !("uncompressed".equalsignorecase(style));
    }

    public boolean equals(object o)
    {
        if (!(o instanceof bcecpublickey))
        {
            return false;
        }

        bcecpublickey other = (bcecpublickey)o;

        return enginegetq().equals(other.enginegetq()) && (enginegetspec().equals(other.enginegetspec()));
    }

    public int hashcode()
    {
        return enginegetq().hashcode() ^ enginegetspec().hashcode();
    }

    private void readobject(
        objectinputstream in)
        throws ioexception, classnotfoundexception
    {
        in.defaultreadobject();

        byte[] enc = (byte[])in.readobject();

        populatefrompubkeyinfo(subjectpublickeyinfo.getinstance(asn1primitive.frombytearray(enc)));

        this.configuration = bouncycastleprovider.configuration;
    }

    private void writeobject(
        objectoutputstream out)
        throws ioexception
    {
        out.defaultwriteobject();

        out.writeobject(this.getencoded());
    }
}
