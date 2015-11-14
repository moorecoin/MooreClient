package org.ripple.bouncycastle.jce.provider;

import java.io.ioexception;
import java.io.objectinputstream;
import java.io.objectoutputstream;
import java.math.biginteger;
import java.util.enumeration;

import javax.crypto.interfaces.dhprivatekey;
import javax.crypto.spec.dhparameterspec;
import javax.crypto.spec.dhprivatekeyspec;

import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1encoding;
import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.derinteger;
import org.ripple.bouncycastle.asn1.derobjectidentifier;
import org.ripple.bouncycastle.asn1.pkcs.dhparameter;
import org.ripple.bouncycastle.asn1.pkcs.pkcsobjectidentifiers;
import org.ripple.bouncycastle.asn1.pkcs.privatekeyinfo;
import org.ripple.bouncycastle.asn1.x509.algorithmidentifier;
import org.ripple.bouncycastle.asn1.x9.dhdomainparameters;
import org.ripple.bouncycastle.asn1.x9.x9objectidentifiers;
import org.ripple.bouncycastle.crypto.params.dhprivatekeyparameters;
import org.ripple.bouncycastle.jcajce.provider.asymmetric.util.pkcs12bagattributecarrierimpl;
import org.ripple.bouncycastle.jce.interfaces.pkcs12bagattributecarrier;

public class jcedhprivatekey
    implements dhprivatekey, pkcs12bagattributecarrier
{
    static final long serialversionuid = 311058815616901812l;
    
    biginteger      x;

    private dhparameterspec dhspec;
    private privatekeyinfo  info;

    private pkcs12bagattributecarrier attrcarrier = new pkcs12bagattributecarrierimpl();

    protected jcedhprivatekey()
    {
    }

    jcedhprivatekey(
        dhprivatekey    key)
    {
        this.x = key.getx();
        this.dhspec = key.getparams();
    }

    jcedhprivatekey(
        dhprivatekeyspec    spec)
    {
        this.x = spec.getx();
        this.dhspec = new dhparameterspec(spec.getp(), spec.getg());
    }

    jcedhprivatekey(
        privatekeyinfo  info)
        throws ioexception
    {
        asn1sequence    seq = asn1sequence.getinstance(info.getalgorithmid().getparameters());
        derinteger      derx = derinteger.getinstance(info.parseprivatekey());
        derobjectidentifier id = info.getalgorithmid().getalgorithm();

        this.info = info;
        this.x = derx.getvalue();

        if (id.equals(pkcsobjectidentifiers.dhkeyagreement))
        {
            dhparameter params = dhparameter.getinstance(seq);

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

    jcedhprivatekey(
        dhprivatekeyparameters  params)
    {
        this.x = params.getx();
        this.dhspec = new dhparameterspec(params.getparameters().getp(), params.getparameters().getg(), params.getparameters().getl());
    }

    public string getalgorithm()
    {
        return "dh";
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
        try
        {
            if (info != null)
            {
                return info.getencoded(asn1encoding.der);
            }

            privatekeyinfo          info = new privatekeyinfo(new algorithmidentifier(pkcsobjectidentifiers.dhkeyagreement, new dhparameter(dhspec.getp(), dhspec.getg(), dhspec.getl())), new derinteger(getx()));

            return info.getencoded(asn1encoding.der);
        }
        catch (ioexception e)
        {
            return null;
        }
    }

    public dhparameterspec getparams()
    {
        return dhspec;
    }

    public biginteger getx()
    {
        return x;
    }

    private void readobject(
        objectinputstream   in)
        throws ioexception, classnotfoundexception
    {
        x = (biginteger)in.readobject();

        this.dhspec = new dhparameterspec((biginteger)in.readobject(), (biginteger)in.readobject(), in.readint());
    }

    private void writeobject(
        objectoutputstream  out)
        throws ioexception
    {
        out.writeobject(this.getx());
        out.writeobject(dhspec.getp());
        out.writeobject(dhspec.getg());
        out.writeint(dhspec.getl());
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
}
