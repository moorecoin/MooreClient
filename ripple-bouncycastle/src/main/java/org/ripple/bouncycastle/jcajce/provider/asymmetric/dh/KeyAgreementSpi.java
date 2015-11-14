package org.ripple.bouncycastle.jcajce.provider.asymmetric.dh;

import java.math.biginteger;
import java.security.invalidalgorithmparameterexception;
import java.security.invalidkeyexception;
import java.security.key;
import java.security.securerandom;
import java.security.spec.algorithmparameterspec;
import java.util.hashtable;

import javax.crypto.secretkey;
import javax.crypto.shortbufferexception;
import javax.crypto.interfaces.dhprivatekey;
import javax.crypto.interfaces.dhpublickey;
import javax.crypto.spec.dhparameterspec;
import javax.crypto.spec.secretkeyspec;

import org.ripple.bouncycastle.crypto.params.desparameters;
import org.ripple.bouncycastle.util.integers;
import org.ripple.bouncycastle.util.strings;

/**
 * diffie-hellman key agreement. there's actually a better way of doing this
 * if you are using long term public keys, see the light-weight version for
 * details.
 */
public class keyagreementspi
    extends javax.crypto.keyagreementspi
{
    private biginteger      x;
    private biginteger      p;
    private biginteger      g;
    private biginteger      result;

    private static final hashtable algorithms = new hashtable();

    static
    {
        integer i64 = integers.valueof(64);
        integer i192 = integers.valueof(192);
        integer i128 = integers.valueof(128);
        integer i256 = integers.valueof(256);

        algorithms.put("des", i64);
        algorithms.put("desede", i192);
        algorithms.put("blowfish", i128);
        algorithms.put("aes", i256);
    }

    private byte[] biginttobytes(
        biginteger    r)
    {
        byte[]    tmp = r.tobytearray();
        
        if (tmp[0] == 0)
        {
            byte[]    ntmp = new byte[tmp.length - 1];
            
            system.arraycopy(tmp, 1, ntmp, 0, ntmp.length);
            return ntmp;
        }
        
        return tmp;
    }
    
    protected key enginedophase(
        key     key,
        boolean lastphase) 
        throws invalidkeyexception, illegalstateexception
    {
        if (x == null)
        {
            throw new illegalstateexception("diffie-hellman not initialised.");
        }

        if (!(key instanceof dhpublickey))
        {
            throw new invalidkeyexception("dhkeyagreement dophase requires dhpublickey");
        }
        dhpublickey pubkey = (dhpublickey)key;

        if (!pubkey.getparams().getg().equals(g) || !pubkey.getparams().getp().equals(p))
        {
            throw new invalidkeyexception("dhpublickey not for this keyagreement!");
        }

        if (lastphase)
        {
            result = ((dhpublickey)key).gety().modpow(x, p);
            return null;
        }
        else
        {
            result = ((dhpublickey)key).gety().modpow(x, p);
        }

        return new bcdhpublickey(result, pubkey.getparams());
    }

    protected byte[] enginegeneratesecret() 
        throws illegalstateexception
    {
        if (x == null)
        {
            throw new illegalstateexception("diffie-hellman not initialised.");
        }

        return biginttobytes(result);
    }

    protected int enginegeneratesecret(
        byte[]  sharedsecret,
        int     offset) 
        throws illegalstateexception, shortbufferexception
    {
        if (x == null)
        {
            throw new illegalstateexception("diffie-hellman not initialised.");
        }

        byte[]  secret = biginttobytes(result);

        if (sharedsecret.length - offset < secret.length)
        {
            throw new shortbufferexception("dhkeyagreement - buffer too short");
        }

        system.arraycopy(secret, 0, sharedsecret, offset, secret.length);

        return secret.length;
    }

    protected secretkey enginegeneratesecret(
        string algorithm) 
    {
        if (x == null)
        {
            throw new illegalstateexception("diffie-hellman not initialised.");
        }

        string algkey = strings.touppercase(algorithm);
        byte[] res = biginttobytes(result);

        if (algorithms.containskey(algkey))
        {
            integer length = (integer)algorithms.get(algkey);

            byte[] key = new byte[length.intvalue() / 8];
            system.arraycopy(res, 0, key, 0, key.length);

            if (algkey.startswith("des"))
            {
                desparameters.setoddparity(key);
            }
            
            return new secretkeyspec(key, algorithm);
        }

        return new secretkeyspec(res, algorithm);
    }

    protected void engineinit(
        key                     key,
        algorithmparameterspec  params,
        securerandom            random) 
        throws invalidkeyexception, invalidalgorithmparameterexception
    {
        if (!(key instanceof dhprivatekey))
        {
            throw new invalidkeyexception("dhkeyagreement requires dhprivatekey for initialisation");
        }
        dhprivatekey    privkey = (dhprivatekey)key;

        if (params != null)
        {
            if (!(params instanceof dhparameterspec))
            {
                throw new invalidalgorithmparameterexception("dhkeyagreement only accepts dhparameterspec");
            }
            dhparameterspec p = (dhparameterspec)params;

            this.p = p.getp();
            this.g = p.getg();
        }
        else
        {
            this.p = privkey.getparams().getp();
            this.g = privkey.getparams().getg();
        }

        this.x = this.result = privkey.getx();
    }

    protected void engineinit(
        key             key,
        securerandom    random) 
        throws invalidkeyexception
    {
        if (!(key instanceof dhprivatekey))
        {
            throw new invalidkeyexception("dhkeyagreement requires dhprivatekey");
        }

        dhprivatekey    privkey = (dhprivatekey)key;

        this.p = privkey.getparams().getp();
        this.g = privkey.getparams().getg();
        this.x = this.result = privkey.getx();
    }
}
