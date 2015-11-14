package org.ripple.bouncycastle.crypto.macs;

import java.util.hashtable;

import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.digest;
import org.ripple.bouncycastle.crypto.extendeddigest;
import org.ripple.bouncycastle.crypto.mac;
import org.ripple.bouncycastle.crypto.params.keyparameter;
import org.ripple.bouncycastle.util.integers;
import org.ripple.bouncycastle.util.memoable;

/**
 * hmac implementation based on rfc2104
 *
 * h(k xor opad, h(k xor ipad, text))
 */
public class hmac
    implements mac
{
    private final static byte ipad = (byte)0x36;
    private final static byte opad = (byte)0x5c;

    private digest digest;
    private int digestsize;
    private int blocklength;
    private memoable ipadstate;
    private memoable opadstate;

    private byte[] inputpad;
    private byte[] outputbuf;

    private static hashtable blocklengths;
    
    static
    {
        blocklengths = new hashtable();
        
        blocklengths.put("gost3411", integers.valueof(32));
        
        blocklengths.put("md2", integers.valueof(16));
        blocklengths.put("md4", integers.valueof(64));
        blocklengths.put("md5", integers.valueof(64));
        
        blocklengths.put("ripemd128", integers.valueof(64));
        blocklengths.put("ripemd160", integers.valueof(64));
        
        blocklengths.put("sha-1", integers.valueof(64));
        blocklengths.put("sha-224", integers.valueof(64));
        blocklengths.put("sha-256", integers.valueof(64));
        blocklengths.put("sha-384", integers.valueof(128));
        blocklengths.put("sha-512", integers.valueof(128));
        
        blocklengths.put("tiger", integers.valueof(64));
        blocklengths.put("whirlpool", integers.valueof(64));
    }
    
    private static int getbytelength(
        digest digest)
    {
        if (digest instanceof extendeddigest)
        {
            return ((extendeddigest)digest).getbytelength();
        }
        
        integer  b = (integer)blocklengths.get(digest.getalgorithmname());
        
        if (b == null)
        {       
            throw new illegalargumentexception("unknown digest passed: " + digest.getalgorithmname());
        }
        
        return b.intvalue();
    }
    
    /**
     * base constructor for one of the standard digest algorithms that the 
     * bytelength of the algorithm is know for.
     * 
     * @param digest the digest.
     */
    public hmac(
        digest digest)
    {
        this(digest, getbytelength(digest));
    }

    private hmac(
        digest digest,
        int    bytelength)
    {
        this.digest = digest;
        this.digestsize = digest.getdigestsize();
        this.blocklength = bytelength;
        this.inputpad = new byte[blocklength];
        this.outputbuf = new byte[blocklength + digestsize];
    }

    public string getalgorithmname()
    {
        return digest.getalgorithmname() + "/hmac";
    }

    public digest getunderlyingdigest()
    {
        return digest;
    }

    public void init(
        cipherparameters params)
    {
        digest.reset();

        byte[] key = ((keyparameter)params).getkey();
        int keylength = key.length;

        if (keylength > blocklength)
        {
            digest.update(key, 0, keylength);
            digest.dofinal(inputpad, 0);
            
            keylength = digestsize;
        }
        else
        {
            system.arraycopy(key, 0, inputpad, 0, keylength);
        }

        for (int i = keylength; i < inputpad.length; i++)
        {
            inputpad[i] = 0;
        }

        system.arraycopy(inputpad, 0, outputbuf, 0, blocklength);

        xorpad(inputpad, blocklength, ipad);
        xorpad(outputbuf, blocklength, opad);

        if (digest instanceof memoable)
        {
            opadstate = ((memoable)digest).copy();

            ((digest)opadstate).update(outputbuf, 0, blocklength);
        }

        digest.update(inputpad, 0, inputpad.length);

        if (digest instanceof memoable)
        {
            ipadstate = ((memoable)digest).copy();
        }
    }

    public int getmacsize()
    {
        return digestsize;
    }

    public void update(
        byte in)
    {
        digest.update(in);
    }

    public void update(
        byte[] in,
        int inoff,
        int len)
    {
        digest.update(in, inoff, len);
    }

    public int dofinal(
        byte[] out,
        int outoff)
    {
        digest.dofinal(outputbuf, blocklength);

        if (opadstate != null)
        {
            ((memoable)digest).reset(opadstate);
            digest.update(outputbuf, blocklength, digest.getdigestsize());
        }
        else
        {
            digest.update(outputbuf, 0, outputbuf.length);
        }

        int len = digest.dofinal(out, outoff);

        for (int i = blocklength; i < outputbuf.length; i++)
        {
            outputbuf[i] = 0;
        }

        if (ipadstate != null)
        {
            ((memoable)digest).reset(ipadstate);
        }
        else
        {
            digest.update(inputpad, 0, inputpad.length);
        }

        return len;
    }

    /**
     * reset the mac generator.
     */
    public void reset()
    {
        /*
         * reset the underlying digest.
         */
        digest.reset();

        /*
         * reinitialize the digest.
         */
        digest.update(inputpad, 0, inputpad.length);
    }

    private static void xorpad(byte[] pad, int len, byte n)
    {
        for (int i = 0; i < len; ++i)
        {
            pad[i] ^= n;
        }
    }
}
