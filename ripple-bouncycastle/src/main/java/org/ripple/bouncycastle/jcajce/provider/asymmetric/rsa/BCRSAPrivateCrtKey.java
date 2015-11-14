package org.ripple.bouncycastle.jcajce.provider.asymmetric.rsa;

import java.io.ioexception;
import java.math.biginteger;
import java.security.interfaces.rsaprivatecrtkey;
import java.security.spec.rsaprivatecrtkeyspec;

import org.ripple.bouncycastle.asn1.dernull;
import org.ripple.bouncycastle.asn1.pkcs.pkcsobjectidentifiers;
import org.ripple.bouncycastle.asn1.pkcs.privatekeyinfo;
import org.ripple.bouncycastle.asn1.pkcs.rsaprivatekey;
import org.ripple.bouncycastle.asn1.x509.algorithmidentifier;
import org.ripple.bouncycastle.crypto.params.rsaprivatecrtkeyparameters;
import org.ripple.bouncycastle.jcajce.provider.asymmetric.util.keyutil;

/**
 * a provider representation for a rsa private key, with crt factors included.
 */
public class bcrsaprivatecrtkey
    extends bcrsaprivatekey
    implements rsaprivatecrtkey
{
    static final long serialversionuid = 7834723820638524718l;
    
    private biginteger  publicexponent;
    private biginteger  primep;
    private biginteger  primeq;
    private biginteger  primeexponentp;
    private biginteger  primeexponentq;
    private biginteger  crtcoefficient;

    /**
     * construct a private key from it's org.bouncycastle.crypto equivalent.
     *
     * @param key the parameters object representing the private key.
     */
    bcrsaprivatecrtkey(
        rsaprivatecrtkeyparameters key)
    {
        super(key);

        this.publicexponent = key.getpublicexponent();
        this.primep = key.getp();
        this.primeq = key.getq();
        this.primeexponentp = key.getdp();
        this.primeexponentq = key.getdq();
        this.crtcoefficient = key.getqinv();
    }

    /**
     * construct a private key from an rsaprivatecrtkeyspec
     *
     * @param spec the spec to be used in construction.
     */
    bcrsaprivatecrtkey(
        rsaprivatecrtkeyspec spec)
    {
        this.modulus = spec.getmodulus();
        this.publicexponent = spec.getpublicexponent();
        this.privateexponent = spec.getprivateexponent();
        this.primep = spec.getprimep();
        this.primeq = spec.getprimeq();
        this.primeexponentp = spec.getprimeexponentp();
        this.primeexponentq = spec.getprimeexponentq();
        this.crtcoefficient = spec.getcrtcoefficient();
    }

    /**
     * construct a private key from another rsaprivatecrtkey.
     *
     * @param key the object implementing the rsaprivatecrtkey interface.
     */
    bcrsaprivatecrtkey(
        rsaprivatecrtkey key)
    {
        this.modulus = key.getmodulus();
        this.publicexponent = key.getpublicexponent();
        this.privateexponent = key.getprivateexponent();
        this.primep = key.getprimep();
        this.primeq = key.getprimeq();
        this.primeexponentp = key.getprimeexponentp();
        this.primeexponentq = key.getprimeexponentq();
        this.crtcoefficient = key.getcrtcoefficient();
    }

    /**
     * construct an rsa key from a private key info object.
     */
    bcrsaprivatecrtkey(
        privatekeyinfo info)
        throws ioexception
    {
        this(rsaprivatekey.getinstance(info.parseprivatekey()));
    }

    /**
     * construct an rsa key from a asn.1 rsa private key object.
     */
    bcrsaprivatecrtkey(
        rsaprivatekey key)
    {
        this.modulus = key.getmodulus();
        this.publicexponent = key.getpublicexponent();
        this.privateexponent = key.getprivateexponent();
        this.primep = key.getprime1();
        this.primeq = key.getprime2();
        this.primeexponentp = key.getexponent1();
        this.primeexponentq = key.getexponent2();
        this.crtcoefficient = key.getcoefficient();
    }

    /**
     * return the encoding format we produce in getencoded().
     *
     * @return the encoding format we produce in getencoded().
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
        return keyutil.getencodedprivatekeyinfo(new algorithmidentifier(pkcsobjectidentifiers.rsaencryption, dernull.instance), new rsaprivatekey(getmodulus(), getpublicexponent(), getprivateexponent(), getprimep(), getprimeq(), getprimeexponentp(), getprimeexponentq(), getcrtcoefficient()));
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

    /**
     * return the prime p.
     *
     * @return the prime p.
     */
    public biginteger getprimep()
    {
        return primep;
    }

    /**
     * return the prime q.
     *
     * @return the prime q.
     */
    public biginteger getprimeq()
    {
        return primeq;
    }

    /**
     * return the prime exponent for p.
     *
     * @return the prime exponent for p.
     */
    public biginteger getprimeexponentp()
    {
        return primeexponentp;
    }

    /**
     * return the prime exponent for q.
     *
     * @return the prime exponent for q.
     */
    public biginteger getprimeexponentq()
    {
        return primeexponentq;
    }

    /**
     * return the crt coefficient.
     *
     * @return the crt coefficient.
     */
    public biginteger getcrtcoefficient()
    {
        return crtcoefficient;
    }

    public int hashcode()
    {
        return this.getmodulus().hashcode()
               ^ this.getpublicexponent().hashcode()
               ^ this.getprivateexponent().hashcode();
    }

    public boolean equals(object o)
    {
        if (o == this)
        {
            return true;
        }

        if (!(o instanceof rsaprivatecrtkey))
        {
            return false;
        }

        rsaprivatecrtkey key = (rsaprivatecrtkey)o;

        return this.getmodulus().equals(key.getmodulus())
         && this.getpublicexponent().equals(key.getpublicexponent())
         && this.getprivateexponent().equals(key.getprivateexponent())
         && this.getprimep().equals(key.getprimep())
         && this.getprimeq().equals(key.getprimeq())
         && this.getprimeexponentp().equals(key.getprimeexponentp())
         && this.getprimeexponentq().equals(key.getprimeexponentq())
         && this.getcrtcoefficient().equals(key.getcrtcoefficient());
    }

    public string tostring()
    {
        stringbuffer    buf = new stringbuffer();
        string          nl = system.getproperty("line.separator");

        buf.append("rsa private crt key").append(nl);
        buf.append("            modulus: ").append(this.getmodulus().tostring(16)).append(nl);
        buf.append("    public exponent: ").append(this.getpublicexponent().tostring(16)).append(nl);
        buf.append("   private exponent: ").append(this.getprivateexponent().tostring(16)).append(nl);
        buf.append("             primep: ").append(this.getprimep().tostring(16)).append(nl);
        buf.append("             primeq: ").append(this.getprimeq().tostring(16)).append(nl);
        buf.append("     primeexponentp: ").append(this.getprimeexponentp().tostring(16)).append(nl);
        buf.append("     primeexponentq: ").append(this.getprimeexponentq().tostring(16)).append(nl);
        buf.append("     crtcoefficient: ").append(this.getcrtcoefficient().tostring(16)).append(nl);

        return buf.tostring();
    }
}
