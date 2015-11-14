package org.ripple.bouncycastle.jcajce.provider.asymmetric.rsa;

import java.io.ioexception;
import java.security.spec.algorithmparameterspec;
import java.security.spec.invalidparameterspecexception;
import java.security.spec.mgf1parameterspec;
import java.security.spec.pssparameterspec;

import javax.crypto.spec.oaepparameterspec;
import javax.crypto.spec.psource;

import org.ripple.bouncycastle.asn1.asn1encoding;
import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1octetstring;
import org.ripple.bouncycastle.asn1.dernull;
import org.ripple.bouncycastle.asn1.deroctetstring;
import org.ripple.bouncycastle.asn1.pkcs.pkcsobjectidentifiers;
import org.ripple.bouncycastle.asn1.pkcs.rsaesoaepparams;
import org.ripple.bouncycastle.asn1.pkcs.rsassapssparams;
import org.ripple.bouncycastle.asn1.x509.algorithmidentifier;
import org.ripple.bouncycastle.jcajce.provider.util.digestfactory;

public abstract class algorithmparametersspi
    extends java.security.algorithmparametersspi
{
    protected boolean isasn1formatstring(string format)
    {
        return format == null || format.equals("asn.1");
    }

    protected algorithmparameterspec enginegetparameterspec(
        class paramspec)
        throws invalidparameterspecexception
    {
        if (paramspec == null)
        {
            throw new nullpointerexception("argument to getparameterspec must not be null");
        }

        return localenginegetparameterspec(paramspec);
    }

    protected abstract algorithmparameterspec localenginegetparameterspec(class paramspec)
        throws invalidparameterspecexception;

    public static class oaep
        extends algorithmparametersspi
    {
        oaepparameterspec currentspec;
    
        /**
         * return the pkcs#1 asn.1 structure rsaes-oaep-params.
         */
        protected byte[] enginegetencoded() 
        {
            algorithmidentifier hashalgorithm = new algorithmidentifier(
                                                            digestfactory.getoid(currentspec.getdigestalgorithm()),
                                                            dernull.instance);
            mgf1parameterspec mgfspec = (mgf1parameterspec)currentspec.getmgfparameters();
            algorithmidentifier maskgenalgorithm = new algorithmidentifier(
                                                            pkcsobjectidentifiers.id_mgf1,
                                                            new algorithmidentifier(digestfactory.getoid(mgfspec.getdigestalgorithm()), dernull.instance));
            psource.pspecified      psource = (psource.pspecified)currentspec.getpsource();
            algorithmidentifier psourcealgorithm = new algorithmidentifier(
                                                            pkcsobjectidentifiers.id_pspecified, new deroctetstring(psource.getvalue()));
            rsaesoaepparams oaepp = new rsaesoaepparams(hashalgorithm, maskgenalgorithm, psourcealgorithm);
    
            try
            {
                return oaepp.getencoded(asn1encoding.der);
            }
            catch (ioexception e)
            {
                throw new runtimeexception("error encoding oaepparameters");
            }
        }
    
        protected byte[] enginegetencoded(
            string format)
        {
            if (isasn1formatstring(format) || format.equalsignorecase("x.509"))
            {
                return enginegetencoded();
            }
    
            return null;
        }
    
        protected algorithmparameterspec localenginegetparameterspec(
            class paramspec)
            throws invalidparameterspecexception
        {
            if (paramspec == oaepparameterspec.class && currentspec != null)
            {
                return currentspec;
            }
    
            throw new invalidparameterspecexception("unknown parameter spec passed to oaep parameters object.");
        }
    
        protected void engineinit(
            algorithmparameterspec paramspec)
            throws invalidparameterspecexception
        {
            if (!(paramspec instanceof oaepparameterspec))
            {
                throw new invalidparameterspecexception("oaepparameterspec required to initialise an oaep algorithm parameters object");
            }
    
            this.currentspec = (oaepparameterspec)paramspec;
        }
    
        protected void engineinit(
            byte[] params) 
            throws ioexception
        {
            try
            {
                rsaesoaepparams oaepp = rsaesoaepparams.getinstance(params);

                currentspec = new oaepparameterspec(
                                       oaepp.gethashalgorithm().getalgorithm().getid(),
                                       oaepp.getmaskgenalgorithm().getalgorithm().getid(), 
                                       new mgf1parameterspec(algorithmidentifier.getinstance(oaepp.getmaskgenalgorithm().getparameters()).getalgorithm().getid()),
                                       new psource.pspecified(asn1octetstring.getinstance(oaepp.getpsourcealgorithm().getparameters()).getoctets()));
            }
            catch (classcastexception e)
            {
                throw new ioexception("not a valid oaep parameter encoding.");
            }
            catch (arrayindexoutofboundsexception e)
            {
                throw new ioexception("not a valid oaep parameter encoding.");
            }
        }
    
        protected void engineinit(
            byte[] params,
            string format)
            throws ioexception
        {
            if (format.equalsignorecase("x.509")
                    || format.equalsignorecase("asn.1"))
            {
                engineinit(params);
            }
            else
            {
                throw new ioexception("unknown parameter format " + format);
            }
        }
    
        protected string enginetostring()
        {
            return "oaep parameters";
        }
    }
    
    public static class pss
        extends algorithmparametersspi
    {  
        pssparameterspec currentspec;
    
        /**
         * return the pkcs#1 asn.1 structure rsassa-pss-params.
         */
        protected byte[] enginegetencoded() 
            throws ioexception
        {
            pssparameterspec pssspec = currentspec;
            algorithmidentifier hashalgorithm = new algorithmidentifier(
                                                digestfactory.getoid(pssspec.getdigestalgorithm()),
                                                dernull.instance);
            mgf1parameterspec mgfspec = (mgf1parameterspec)pssspec.getmgfparameters();
            algorithmidentifier maskgenalgorithm = new algorithmidentifier(
                                                pkcsobjectidentifiers.id_mgf1,
                                                new algorithmidentifier(digestfactory.getoid(mgfspec.getdigestalgorithm()), dernull.instance));
            rsassapssparams pssp = new rsassapssparams(hashalgorithm, maskgenalgorithm, new asn1integer(pssspec.getsaltlength()), new asn1integer(pssspec.gettrailerfield()));
            
            return pssp.getencoded("der");
        }
    
        protected byte[] enginegetencoded(
            string format)
            throws ioexception
        {
            if (format.equalsignorecase("x.509")
                    || format.equalsignorecase("asn.1"))
            {
                return enginegetencoded();
            }
    
            return null;
        }
    
        protected algorithmparameterspec localenginegetparameterspec(
            class paramspec)
            throws invalidparameterspecexception
        {
            if (paramspec == pssparameterspec.class && currentspec != null)
            {
                return currentspec;
            }
    
            throw new invalidparameterspecexception("unknown parameter spec passed to pss parameters object.");
        }
    
        protected void engineinit(
            algorithmparameterspec paramspec)
            throws invalidparameterspecexception
        {
            if (!(paramspec instanceof pssparameterspec))
            {
                throw new invalidparameterspecexception("pssparameterspec required to initialise an pss algorithm parameters object");
            }
    
            this.currentspec = (pssparameterspec)paramspec;
        }
    
        protected void engineinit(
            byte[] params) 
            throws ioexception
        {
            try
            {
                rsassapssparams pssp = rsassapssparams.getinstance(params);

                currentspec = new pssparameterspec(
                                       pssp.gethashalgorithm().getalgorithm().getid(), 
                                       pssp.getmaskgenalgorithm().getalgorithm().getid(), 
                                       new mgf1parameterspec(algorithmidentifier.getinstance(pssp.getmaskgenalgorithm().getparameters()).getalgorithm().getid()),
                                       pssp.getsaltlength().intvalue(),
                                       pssp.gettrailerfield().intvalue());
            }
            catch (classcastexception e)
            {
                throw new ioexception("not a valid pss parameter encoding.");
            }
            catch (arrayindexoutofboundsexception e)
            {
                throw new ioexception("not a valid pss parameter encoding.");
            }
        }
    
        protected void engineinit(
            byte[] params,
            string format)
            throws ioexception
        {
            if (isasn1formatstring(format) || format.equalsignorecase("x.509"))
            {
                engineinit(params);
            }
            else
            {
                throw new ioexception("unknown parameter format " + format);
            }
        }
    
        protected string enginetostring()
        {
            return "pss parameters";
        }
    }
}
