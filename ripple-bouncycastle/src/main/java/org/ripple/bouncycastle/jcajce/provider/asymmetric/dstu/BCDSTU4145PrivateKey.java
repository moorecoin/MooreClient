package org.ripple.bouncycastle.jcajce.provider.asymmetric.dstu;

import java.io.ioexception;
import java.io.objectinputstream;
import java.io.objectoutputstream;
import java.math.biginteger;
import java.security.interfaces.ecprivatekey;
import java.security.spec.ecparameterspec;
import java.security.spec.ecpoint;
import java.security.spec.ecprivatekeyspec;
import java.security.spec.ellipticcurve;
import java.util.enumeration;

import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1encoding;
import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.derbitstring;
import org.ripple.bouncycastle.asn1.derinteger;
import org.ripple.bouncycastle.asn1.dernull;
import org.ripple.bouncycastle.asn1.derobjectidentifier;
import org.ripple.bouncycastle.asn1.pkcs.privatekeyinfo;
import org.ripple.bouncycastle.asn1.ua.dstu4145namedcurves;
import org.ripple.bouncycastle.asn1.ua.uaobjectidentifiers;
import org.ripple.bouncycastle.asn1.x509.algorithmidentifier;
import org.ripple.bouncycastle.asn1.x509.subjectpublickeyinfo;
import org.ripple.bouncycastle.asn1.x9.x962parameters;
import org.ripple.bouncycastle.asn1.x9.x9ecparameters;
import org.ripple.bouncycastle.asn1.x9.x9objectidentifiers;
import org.ripple.bouncycastle.crypto.params.ecdomainparameters;
import org.ripple.bouncycastle.crypto.params.ecprivatekeyparameters;
import org.ripple.bouncycastle.jcajce.provider.asymmetric.util.ec5util;
import org.ripple.bouncycastle.jcajce.provider.asymmetric.util.ecutil;
import org.ripple.bouncycastle.jcajce.provider.asymmetric.util.pkcs12bagattributecarrierimpl;
import org.ripple.bouncycastle.jce.interfaces.ecpointencoder;
import org.ripple.bouncycastle.jce.interfaces.pkcs12bagattributecarrier;
import org.ripple.bouncycastle.jce.provider.bouncycastleprovider;
import org.ripple.bouncycastle.jce.spec.ecnamedcurvespec;
import org.ripple.bouncycastle.math.ec.eccurve;

public class bcdstu4145privatekey
    implements ecprivatekey, org.ripple.bouncycastle.jce.interfaces.ecprivatekey, pkcs12bagattributecarrier, ecpointencoder
{
    static final long serialversionuid = 7245981689601667138l;

    private string algorithm = "dstu4145";
    private boolean withcompression;

    private transient biginteger d;
    private transient ecparameterspec ecspec;
    private transient derbitstring publickey;
    private transient pkcs12bagattributecarrierimpl attrcarrier = new pkcs12bagattributecarrierimpl();

    protected bcdstu4145privatekey()
    {
    }

    public bcdstu4145privatekey(
        ecprivatekey key)
    {
        this.d = key.gets();
        this.algorithm = key.getalgorithm();
        this.ecspec = key.getparams();
    }

    public bcdstu4145privatekey(
        org.ripple.bouncycastle.jce.spec.ecprivatekeyspec spec)
    {
        this.d = spec.getd();

        if (spec.getparams() != null) // can be null if implicitlyca
        {
            eccurve curve = spec.getparams().getcurve();
            ellipticcurve ellipticcurve;

            ellipticcurve = ec5util.convertcurve(curve, spec.getparams().getseed());

            this.ecspec = ec5util.convertspec(ellipticcurve, spec.getparams());
        }
        else
        {
            this.ecspec = null;
        }
    }


    public bcdstu4145privatekey(
        ecprivatekeyspec spec)
    {
        this.d = spec.gets();
        this.ecspec = spec.getparams();
    }

    public bcdstu4145privatekey(
        bcdstu4145privatekey key)
    {
        this.d = key.d;
        this.ecspec = key.ecspec;
        this.withcompression = key.withcompression;
        this.attrcarrier = key.attrcarrier;
        this.publickey = key.publickey;
    }

    public bcdstu4145privatekey(
        string algorithm,
        ecprivatekeyparameters params,
        bcdstu4145publickey pubkey,
        ecparameterspec spec)
    {
        ecdomainparameters dp = params.getparameters();

        this.algorithm = algorithm;
        this.d = params.getd();

        if (spec == null)
        {
            ellipticcurve ellipticcurve = ec5util.convertcurve(dp.getcurve(), dp.getseed());

            this.ecspec = new ecparameterspec(
                ellipticcurve,
                new ecpoint(
                    dp.getg().getx().tobiginteger(),
                    dp.getg().gety().tobiginteger()),
                dp.getn(),
                dp.geth().intvalue());
        }
        else
        {
            this.ecspec = spec;
        }

        publickey = getpublickeydetails(pubkey);
    }

    public bcdstu4145privatekey(
        string algorithm,
        ecprivatekeyparameters params,
        bcdstu4145publickey pubkey,
        org.ripple.bouncycastle.jce.spec.ecparameterspec spec)
    {
        ecdomainparameters dp = params.getparameters();

        this.algorithm = algorithm;
        this.d = params.getd();

        if (spec == null)
        {
            ellipticcurve ellipticcurve = ec5util.convertcurve(dp.getcurve(), dp.getseed());

            this.ecspec = new ecparameterspec(
                ellipticcurve,
                new ecpoint(
                    dp.getg().getx().tobiginteger(),
                    dp.getg().gety().tobiginteger()),
                dp.getn(),
                dp.geth().intvalue());
        }
        else
        {
            ellipticcurve ellipticcurve = ec5util.convertcurve(spec.getcurve(), spec.getseed());

            this.ecspec = new ecparameterspec(
                ellipticcurve,
                new ecpoint(
                    spec.getg().getx().tobiginteger(),
                    spec.getg().gety().tobiginteger()),
                spec.getn(),
                spec.geth().intvalue());
        }

        publickey = getpublickeydetails(pubkey);
    }

    public bcdstu4145privatekey(
        string algorithm,
        ecprivatekeyparameters params)
    {
        this.algorithm = algorithm;
        this.d = params.getd();
        this.ecspec = null;
    }

    bcdstu4145privatekey(
        privatekeyinfo info)
        throws ioexception
    {
        populatefromprivkeyinfo(info);
    }

    private void populatefromprivkeyinfo(privatekeyinfo info)
        throws ioexception
    {
        x962parameters params = new x962parameters((asn1primitive)info.getprivatekeyalgorithm().getparameters());

        if (params.isnamedcurve())
        {
            asn1objectidentifier oid = asn1objectidentifier.getinstance(params.getparameters());
            x9ecparameters ecp = ecutil.getnamedcurvebyoid(oid);

            if (ecp == null) // dstu curve
            {
                ecdomainparameters gparam = dstu4145namedcurves.getbyoid(oid);
                ellipticcurve ellipticcurve = ec5util.convertcurve(gparam.getcurve(), gparam.getseed());

                ecspec = new ecnamedcurvespec(
                    oid.getid(),
                    ellipticcurve,
                    new ecpoint(
                        gparam.getg().getx().tobiginteger(),
                        gparam.getg().gety().tobiginteger()),
                    gparam.getn(),
                    gparam.geth());
            }
            else
            {
                ellipticcurve ellipticcurve = ec5util.convertcurve(ecp.getcurve(), ecp.getseed());

                ecspec = new ecnamedcurvespec(
                    ecutil.getcurvename(oid),
                    ellipticcurve,
                    new ecpoint(
                        ecp.getg().getx().tobiginteger(),
                        ecp.getg().gety().tobiginteger()),
                    ecp.getn(),
                    ecp.geth());
            }
        }
        else if (params.isimplicitlyca())
        {
            ecspec = null;
        }
        else
        {
            x9ecparameters ecp = x9ecparameters.getinstance(params.getparameters());
            ellipticcurve ellipticcurve = ec5util.convertcurve(ecp.getcurve(), ecp.getseed());

            this.ecspec = new ecparameterspec(
                ellipticcurve,
                new ecpoint(
                    ecp.getg().getx().tobiginteger(),
                    ecp.getg().gety().tobiginteger()),
                ecp.getn(),
                ecp.geth().intvalue());
        }

        asn1encodable privkey = info.parseprivatekey();
        if (privkey instanceof derinteger)
        {
            derinteger derd = derinteger.getinstance(privkey);

            this.d = derd.getvalue();
        }
        else
        {
            org.ripple.bouncycastle.asn1.sec.ecprivatekey ec = org.ripple.bouncycastle.asn1.sec.ecprivatekey.getinstance(privkey);

            this.d = ec.getkey();
            this.publickey = ec.getpublickey();
        }
    }

    public string getalgorithm()
    {
        return algorithm;
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
        x962parameters params;

        if (ecspec instanceof ecnamedcurvespec)
        {
            derobjectidentifier curveoid = ecutil.getnamedcurveoid(((ecnamedcurvespec)ecspec).getname());
            if (curveoid == null)  // guess it's the oid
            {
                curveoid = new derobjectidentifier(((ecnamedcurvespec)ecspec).getname());
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

        privatekeyinfo info;
        org.ripple.bouncycastle.asn1.sec.ecprivatekey keystructure;

        if (publickey != null)
        {
            keystructure = new org.ripple.bouncycastle.asn1.sec.ecprivatekey(this.gets(), publickey, params);
        }
        else
        {
            keystructure = new org.ripple.bouncycastle.asn1.sec.ecprivatekey(this.gets(), params);
        }

        try
        {
            if (algorithm.equals("dstu4145"))
            {
                info = new privatekeyinfo(new algorithmidentifier(uaobjectidentifiers.dstu4145be, params.toasn1primitive()), keystructure.toasn1primitive());
            }
            else
            {

                info = new privatekeyinfo(new algorithmidentifier(x9objectidentifiers.id_ecpublickey, params.toasn1primitive()), keystructure.toasn1primitive());
            }

            return info.getencoded(asn1encoding.der);
        }
        catch (ioexception e)
        {
            return null;
        }
    }

    public ecparameterspec getparams()
    {
        return ecspec;
    }

    public org.ripple.bouncycastle.jce.spec.ecparameterspec getparameters()
    {
        if (ecspec == null)
        {
            return null;
        }

        return ec5util.convertspec(ecspec, withcompression);
    }

    org.ripple.bouncycastle.jce.spec.ecparameterspec enginegetspec()
    {
        if (ecspec != null)
        {
            return ec5util.convertspec(ecspec, withcompression);
        }

        return bouncycastleprovider.configuration.getecimplicitlyca();
    }

    public biginteger gets()
    {
        return d;
    }

    public biginteger getd()
    {
        return d;
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

    public void setpointformat(string style)
    {
        withcompression = !("uncompressed".equalsignorecase(style));
    }

    public boolean equals(object o)
    {
        if (!(o instanceof bcdstu4145privatekey))
        {
            return false;
        }

        bcdstu4145privatekey other = (bcdstu4145privatekey)o;

        return getd().equals(other.getd()) && (enginegetspec().equals(other.enginegetspec()));
    }

    public int hashcode()
    {
        return getd().hashcode() ^ enginegetspec().hashcode();
    }

    public string tostring()
    {
        stringbuffer buf = new stringbuffer();
        string nl = system.getproperty("line.separator");

        buf.append("ec private key").append(nl);
        buf.append("             s: ").append(this.d.tostring(16)).append(nl);

        return buf.tostring();

    }

    private derbitstring getpublickeydetails(bcdstu4145publickey pub)
    {
        try
        {
            subjectpublickeyinfo info = subjectpublickeyinfo.getinstance(asn1primitive.frombytearray(pub.getencoded()));

            return info.getpublickeydata();
        }
        catch (ioexception e)
        {   // should never happen
            return null;
        }
    }

    private void readobject(
        objectinputstream in)
        throws ioexception, classnotfoundexception
    {
        in.defaultreadobject();

        byte[] enc = (byte[])in.readobject();

        populatefromprivkeyinfo(privatekeyinfo.getinstance(asn1primitive.frombytearray(enc)));

        this.attrcarrier = new pkcs12bagattributecarrierimpl();
    }

    private void writeobject(
        objectoutputstream out)
        throws ioexception
    {
        out.defaultwriteobject();

        out.writeobject(this.getencoded());
    }
}
