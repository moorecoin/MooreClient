package org.ripple.bouncycastle.pqc.jcajce.provider.gmss;

import java.security.publickey;

import org.ripple.bouncycastle.asn1.x509.algorithmidentifier;
import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.pqc.asn1.gmsspublickey;
import org.ripple.bouncycastle.pqc.asn1.pqcobjectidentifiers;
import org.ripple.bouncycastle.pqc.asn1.parset;
import org.ripple.bouncycastle.pqc.crypto.gmss.gmssparameters;
import org.ripple.bouncycastle.pqc.crypto.gmss.gmsspublickeyparameters;
import org.ripple.bouncycastle.pqc.jcajce.provider.util.keyutil;
import org.ripple.bouncycastle.pqc.jcajce.spec.gmsspublickeyspec;
import org.ripple.bouncycastle.util.encoders.hex;

/**
 * this class implements the gmss public key and is usually initiated by the <a
 * href="gmsskeypairgenerator">gmsskeypairgenerator</a>.
 *
 * @see org.ripple.bouncycastle.pqc.crypto.gmss.gmsskeypairgenerator
 * @see org.ripple.bouncycastle.pqc.jcajce.spec.gmsspublickeyspec
 */
public class bcgmsspublickey
    implements cipherparameters, publickey
{

    /**
     *
     */
    private static final long serialversionuid = 1l;

    /**
     * the gmss public key
     */
    private byte[] publickeybytes;

    /**
     * the gmssparameterset
     */
    private gmssparameters gmssparameterset;


    private gmssparameters gmssparams;

    /**
     * the constructor
     *
     * @param pub              a raw gmss public key
     * @param gmssparameterset an instance of gmss parameterset
     * @see org.ripple.bouncycastle.pqc.crypto.gmss.gmsskeypairgenerator
     */
    public bcgmsspublickey(byte[] pub, gmssparameters gmssparameterset)
    {
        this.gmssparameterset = gmssparameterset;
        this.publickeybytes = pub;
    }

    /**
     * the constructor
     *
     * @param keyspec a gmss key specification
     */
    protected bcgmsspublickey(gmsspublickeyspec keyspec)
    {
        this(keyspec.getpublickey(), keyspec.getparameters());
    }

    public bcgmsspublickey(
        gmsspublickeyparameters params)
    {
        this(params.getpublickey(), params.getparameters());
    }

    /**
     * returns the name of the algorithm
     *
     * @return "gmss"
     */
    public string getalgorithm()
    {
        return "gmss";
    }

    /**
     * @return the gmss public key byte array
     */
    public byte[] getpublickeybytes()
    {
        return publickeybytes;
    }

    /**
     * @return the gmss parameterset
     */
    public gmssparameters getparameterset()
    {
        return gmssparameterset;
    }

    /**
     * returns a human readable form of the gmss public key
     *
     * @return a human readable form of the gmss public key
     */
    public string tostring()
    {
        string out = "gmss public key : "
            + new string(hex.encode(publickeybytes)) + "\n"
            + "height of trees: \n";

        for (int i = 0; i < gmssparameterset.getheightoftrees().length; i++)
        {
            out = out + "layer " + i + " : "
                + gmssparameterset.getheightoftrees()[i]
                + " winternitzparameter: "
                + gmssparameterset.getwinternitzparameter()[i] + " k: "
                + gmssparameterset.getk()[i] + "\n";
        }
        return out;
    }

    public byte[] getencoded()
    {
        return keyutil.getencodedsubjectpublickeyinfo(new algorithmidentifier(pqcobjectidentifiers.gmss, new parset(gmssparameterset.getnumoflayers(), gmssparameterset.getheightoftrees(), gmssparameterset.getwinternitzparameter(), gmssparameterset.getk()).toasn1primitive()), new gmsspublickey(publickeybytes));
    }

    public string getformat()
    {
        return "x.509";
    }
}
