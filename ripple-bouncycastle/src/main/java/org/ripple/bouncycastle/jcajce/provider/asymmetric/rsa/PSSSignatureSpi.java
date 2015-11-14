package org.ripple.bouncycastle.jcajce.provider.asymmetric.rsa;

import java.io.bytearrayoutputstream;
import java.security.algorithmparameters;
import java.security.invalidkeyexception;
import java.security.invalidparameterexception;
import java.security.privatekey;
import java.security.publickey;
import java.security.securerandom;
import java.security.signatureexception;
import java.security.signaturespi;
import java.security.interfaces.rsaprivatekey;
import java.security.interfaces.rsapublickey;
import java.security.spec.algorithmparameterspec;
import java.security.spec.mgf1parameterspec;
import java.security.spec.pssparameterspec;

import org.ripple.bouncycastle.asn1.pkcs.pkcsobjectidentifiers;
import org.ripple.bouncycastle.crypto.asymmetricblockcipher;
import org.ripple.bouncycastle.crypto.cryptoexception;
import org.ripple.bouncycastle.crypto.digest;
import org.ripple.bouncycastle.crypto.engines.rsablindedengine;
import org.ripple.bouncycastle.crypto.params.parameterswithrandom;
import org.ripple.bouncycastle.jcajce.provider.util.digestfactory;
import org.ripple.bouncycastle.jce.provider.bouncycastleprovider;

public class psssignaturespi
    extends signaturespi
{
    private algorithmparameters engineparams;
    private pssparameterspec paramspec;
    private pssparameterspec originalspec;
    private asymmetricblockcipher signer;
    private digest contentdigest;
    private digest mgfdigest;
    private int saltlength;
    private byte trailer;
    private boolean israw;

    private org.ripple.bouncycastle.crypto.signers.psssigner pss;

    private byte gettrailer(
        int trailerfield)
    {
        if (trailerfield == 1)
        {
            return org.ripple.bouncycastle.crypto.signers.psssigner.trailer_implicit;
        }
        
        throw new illegalargumentexception("unknown trailer field");
    }

    private void setupcontentdigest()
    {
        if (israw)
        {
            this.contentdigest = new nullpssdigest(mgfdigest);
        }
        else
        {
            this.contentdigest = mgfdigest;
        }
    }

    // care - this constructor is actually used by outside organisations
    protected psssignaturespi(
        asymmetricblockcipher signer,
        pssparameterspec paramspecarg)
    {
        this(signer, paramspecarg, false);
    }

    // care - this constructor is actually used by outside organisations
    protected psssignaturespi(
        asymmetricblockcipher signer,
        pssparameterspec baseparamspec,
        boolean israw)
    {
        this.signer = signer;
        this.originalspec = baseparamspec;
        
        if (baseparamspec == null)
        {
            this.paramspec = pssparameterspec.default;
        }
        else
        {
            this.paramspec = baseparamspec;
        }

        this.mgfdigest = digestfactory.getdigest(paramspec.getdigestalgorithm());
        this.saltlength = paramspec.getsaltlength();
        this.trailer = gettrailer(paramspec.gettrailerfield());
        this.israw = israw;

        setupcontentdigest();
    }
    
    protected void engineinitverify(
        publickey publickey)
        throws invalidkeyexception
    {
        if (!(publickey instanceof rsapublickey))
        {
            throw new invalidkeyexception("supplied key is not a rsapublickey instance");
        }

        pss = new org.ripple.bouncycastle.crypto.signers.psssigner(signer, contentdigest, mgfdigest, saltlength, trailer);
        pss.init(false,
            rsautil.generatepublickeyparameter((rsapublickey)publickey));
    }

    protected void engineinitsign(
        privatekey privatekey,
        securerandom random)
        throws invalidkeyexception
    {
        if (!(privatekey instanceof rsaprivatekey))
        {
            throw new invalidkeyexception("supplied key is not a rsaprivatekey instance");
        }

        pss = new org.ripple.bouncycastle.crypto.signers.psssigner(signer, contentdigest, mgfdigest, saltlength, trailer);
        pss.init(true, new parameterswithrandom(rsautil.generateprivatekeyparameter((rsaprivatekey)privatekey), random));
    }

    protected void engineinitsign(
        privatekey privatekey)
        throws invalidkeyexception
    {
        if (!(privatekey instanceof rsaprivatekey))
        {
            throw new invalidkeyexception("supplied key is not a rsaprivatekey instance");
        }

        pss = new org.ripple.bouncycastle.crypto.signers.psssigner(signer, contentdigest, mgfdigest, saltlength, trailer);
        pss.init(true, rsautil.generateprivatekeyparameter((rsaprivatekey)privatekey));
    }

    protected void engineupdate(
        byte    b)
        throws signatureexception
    {
        pss.update(b);
    }

    protected void engineupdate(
        byte[]  b,
        int     off,
        int     len) 
        throws signatureexception
    {
        pss.update(b, off, len);
    }

    protected byte[] enginesign()
        throws signatureexception
    {
        try
        {
            return pss.generatesignature();
        }
        catch (cryptoexception e)
        {
            throw new signatureexception(e.getmessage());
        }
    }

    protected boolean engineverify(
        byte[]  sigbytes) 
        throws signatureexception
    {
        return pss.verifysignature(sigbytes);
    }

    protected void enginesetparameter(
        algorithmparameterspec params)
        throws invalidparameterexception
    {
        if (params instanceof pssparameterspec)
        {
            pssparameterspec newparamspec = (pssparameterspec)params;
            
            if (originalspec != null)
            {
                if (!digestfactory.issamedigest(originalspec.getdigestalgorithm(), newparamspec.getdigestalgorithm()))
                {
                    throw new invalidparameterexception("parameter must be using " + originalspec.getdigestalgorithm());
                }
            }
            if (!newparamspec.getmgfalgorithm().equalsignorecase("mgf1") && !newparamspec.getmgfalgorithm().equals(pkcsobjectidentifiers.id_mgf1.getid()))
            {
                throw new invalidparameterexception("unknown mask generation function specified");
            }
            
            if (!(newparamspec.getmgfparameters() instanceof mgf1parameterspec))
            {
                throw new invalidparameterexception("unkown mgf parameters");
            }
            
            mgf1parameterspec mgfparams = (mgf1parameterspec)newparamspec.getmgfparameters();
            
            if (!digestfactory.issamedigest(mgfparams.getdigestalgorithm(), newparamspec.getdigestalgorithm()))
            {
                throw new invalidparameterexception("digest algorithm for mgf should be the same as for pss parameters.");
            }
            
            digest newdigest = digestfactory.getdigest(mgfparams.getdigestalgorithm());
            
            if (newdigest == null)
            {
                throw new invalidparameterexception("no match on mgf digest algorithm: "+ mgfparams.getdigestalgorithm());
            }

            this.engineparams = null;
            this.paramspec = newparamspec;
            this.mgfdigest = newdigest;
            this.saltlength = paramspec.getsaltlength();
            this.trailer = gettrailer(paramspec.gettrailerfield());

            setupcontentdigest();
        }
        else
        {
            throw new invalidparameterexception("only pssparameterspec supported");
        }
    }

    protected algorithmparameters enginegetparameters()
    {
        if (engineparams == null)
        {
            if (paramspec != null)
            {
                try
                {
                    engineparams = algorithmparameters.getinstance("pss", bouncycastleprovider.provider_name);
                    engineparams.init(paramspec);
                }
                catch (exception e)
                {
                    throw new runtimeexception(e.tostring());
                }
            }
        }

        return engineparams;
    }
    
    /**
     * @deprecated replaced with <a href = "#enginesetparameter(java.security.spec.algorithmparameterspec)">
     */
    protected void enginesetparameter(
        string param,
        object value)
    {
        throw new unsupportedoperationexception("enginesetparameter unsupported");
    }
    
    protected object enginegetparameter(
        string param)
    {
        throw new unsupportedoperationexception("enginegetparameter unsupported");
    }

    static public class nonepss
        extends psssignaturespi
    {
        public nonepss()
        {
            super(new rsablindedengine(), null, true);
        }
    }

    static public class psswithrsa
        extends psssignaturespi
    {
        public psswithrsa()
        {
            super(new rsablindedengine(), null);
        }
    }
    
    static public class sha1withrsa
        extends psssignaturespi
    {
        public sha1withrsa()
        {
            super(new rsablindedengine(), pssparameterspec.default);
        }
    }

    static public class sha224withrsa
        extends psssignaturespi
    {
        public sha224withrsa()
        {
            super(new rsablindedengine(), new pssparameterspec("sha-224", "mgf1", new mgf1parameterspec("sha-224"), 28, 1));
        }
    }
    
    static public class sha256withrsa
        extends psssignaturespi
    {
        public sha256withrsa()
        {
            super(new rsablindedengine(), new pssparameterspec("sha-256", "mgf1", new mgf1parameterspec("sha-256"), 32, 1));
        }
    }

    static public class sha384withrsa
        extends psssignaturespi
    {
        public sha384withrsa()
        {
            super(new rsablindedengine(), new pssparameterspec("sha-384", "mgf1", new mgf1parameterspec("sha-384"), 48, 1));
        }
    }

    static public class sha512withrsa
        extends psssignaturespi
    {
        public sha512withrsa()
        {
            super(new rsablindedengine(), new pssparameterspec("sha-512", "mgf1", new mgf1parameterspec("sha-512"), 64, 1));
        }
    }

    private class nullpssdigest
        implements digest
    {
        private bytearrayoutputstream bout = new bytearrayoutputstream();
        private digest basedigest;
        private boolean oddtime = true;

        public nullpssdigest(digest mgfdigest)
        {
            this.basedigest = mgfdigest;
        }

        public string getalgorithmname()
        {
            return "null";
        }

        public int getdigestsize()
        {
            return basedigest.getdigestsize();
        }

        public void update(byte in)
        {
            bout.write(in);
        }

        public void update(byte[] in, int inoff, int len)
        {
            bout.write(in, inoff, len);
        }

        public int dofinal(byte[] out, int outoff)
        {
            byte[] res = bout.tobytearray();

            if (oddtime)
            {
                system.arraycopy(res, 0, out, outoff, res.length);
            }
            else
            {
                basedigest.update(res, 0, res.length);

                basedigest.dofinal(out, outoff);
            }

            reset();

            oddtime = !oddtime;

            return res.length;
        }

        public void reset()
        {
            bout.reset();
            basedigest.reset();
        }

        public int getbytelength()
        {
            return 0;
        }
    }
}
