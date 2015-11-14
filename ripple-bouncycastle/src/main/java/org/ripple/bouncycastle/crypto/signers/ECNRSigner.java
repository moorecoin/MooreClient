package org.ripple.bouncycastle.crypto.signers;

import org.ripple.bouncycastle.crypto.asymmetriccipherkeypair;
import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.dsa;
import org.ripple.bouncycastle.crypto.datalengthexception;
import org.ripple.bouncycastle.crypto.generators.eckeypairgenerator;
import org.ripple.bouncycastle.crypto.params.eckeygenerationparameters;
import org.ripple.bouncycastle.crypto.params.eckeyparameters;
import org.ripple.bouncycastle.crypto.params.ecprivatekeyparameters;
import org.ripple.bouncycastle.crypto.params.ecpublickeyparameters;
import org.ripple.bouncycastle.crypto.params.parameterswithrandom;
import org.ripple.bouncycastle.math.ec.ecalgorithms;
import org.ripple.bouncycastle.math.ec.ecconstants;
import org.ripple.bouncycastle.math.ec.ecpoint;

import java.math.biginteger;
import java.security.securerandom;

/**
 * ec-nr as described in ieee 1363-2000
 */
public class ecnrsigner
    implements dsa
{
    private boolean             forsigning;
    private eckeyparameters     key;
    private securerandom        random;

    public void init(
        boolean          forsigning, 
        cipherparameters param) 
    {
        this.forsigning = forsigning;
        
        if (forsigning)
        {
            if (param instanceof parameterswithrandom)
            {
                parameterswithrandom    rparam = (parameterswithrandom)param;

                this.random = rparam.getrandom();
                this.key = (ecprivatekeyparameters)rparam.getparameters();
            }
            else
            {
                this.random = new securerandom();
                this.key = (ecprivatekeyparameters)param;
            }
        }
        else
        {
            this.key = (ecpublickeyparameters)param;
        }
    }

    // section 7.2.5 ecsp-nr, pg 34
    /**
     * generate a signature for the given message using the key we were
     * initialised with.  generally, the order of the curve should be at 
     * least as long as the hash of the message of interest, and with 
     * ecnr it *must* be at least as long.  
     *
     * @param digest  the digest to be signed.
     * @exception datalengthexception if the digest is longer than the key allows
     */
    public biginteger[] generatesignature(
        byte[] digest)
    {
        if (! this.forsigning) 
        {
            throw new illegalstateexception("not initialised for signing");
        }
        
        biginteger n = ((ecprivatekeyparameters)this.key).getparameters().getn();
        int nbitlength = n.bitlength();
        
        biginteger e = new biginteger(1, digest);
        int ebitlength = e.bitlength();
        
        ecprivatekeyparameters  privkey = (ecprivatekeyparameters)key;
               
        if (ebitlength > nbitlength) 
        {
            throw new datalengthexception("input too large for ecnr key.");
        }

        biginteger r = null;
        biginteger s = null;

        asymmetriccipherkeypair temppair;
        do // generate r
        {
            // generate another, but very temporary, key pair using 
            // the same ec parameters
            eckeypairgenerator keygen = new eckeypairgenerator();
            
            keygen.init(new eckeygenerationparameters(privkey.getparameters(), this.random));
            
            temppair = keygen.generatekeypair();

            //    biginteger vx = temppair.getpublic().getw().getaffinex();
            ecpublickeyparameters v = (ecpublickeyparameters)temppair.getpublic();        // get temp's public key
            biginteger vx = v.getq().getx().tobiginteger();        // get the point's x coordinate
            
            r = vx.add(e).mod(n);
        }
        while (r.equals(ecconstants.zero));

        // generate s
        biginteger x = privkey.getd();                // private key value
        biginteger u = ((ecprivatekeyparameters)temppair.getprivate()).getd();    // temp's private key value
        s = u.subtract(r.multiply(x)).mod(n);

        biginteger[]  res = new biginteger[2];
        res[0] = r;
        res[1] = s;

        return res;
    }

    // section 7.2.6 ecvp-nr, pg 35
    /**
     * return true if the value r and s represent a signature for the 
     * message passed in. generally, the order of the curve should be at 
     * least as long as the hash of the message of interest, and with 
     * ecnr, it *must* be at least as long.  but just in case the signer
     * applied mod(n) to the longer digest, this implementation will
     * apply mod(n) during verification.
     *
     * @param digest  the digest to be verified.
     * @param r       the r value of the signature.
     * @param s       the s value of the signature.
     * @exception datalengthexception if the digest is longer than the key allows
     */
    public boolean verifysignature(
        byte[]      digest,
        biginteger  r,
        biginteger  s)
    {
        if (this.forsigning) 
        {
            throw new illegalstateexception("not initialised for verifying");
        }

        ecpublickeyparameters pubkey = (ecpublickeyparameters)key;
        biginteger n = pubkey.getparameters().getn();
        int nbitlength = n.bitlength();
        
        biginteger e = new biginteger(1, digest);
        int ebitlength = e.bitlength();
        
        if (ebitlength > nbitlength) 
        {
            throw new datalengthexception("input too large for ecnr key.");
        }
        
        // r in the range [1,n-1]
        if (r.compareto(ecconstants.one) < 0 || r.compareto(n) >= 0) 
        {
            return false;
        }

        // s in the range [0,n-1]           nb: ecnr spec says 0
        if (s.compareto(ecconstants.zero) < 0 || s.compareto(n) >= 0) 
        {
            return false;
        }

        // compute p = sg + rw

        ecpoint g = pubkey.getparameters().getg();
        ecpoint w = pubkey.getq();
        // calculate p using bouncy math
        ecpoint p = ecalgorithms.sumoftwomultiplies(g, s, w, r);

        // components must be bogus.
        if (p.isinfinity())
        {
            return false;
        }

        biginteger x = p.getx().tobiginteger();
        biginteger t = r.subtract(x).mod(n);

        return t.equals(e);
    }
}
