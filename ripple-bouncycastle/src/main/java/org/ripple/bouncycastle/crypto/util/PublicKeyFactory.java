package org.ripple.bouncycastle.crypto.util;

import java.io.ioexception;
import java.io.inputstream;
import java.math.biginteger;

import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1inputstream;
import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.asn1octetstring;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.deroctetstring;
import org.ripple.bouncycastle.asn1.nist.nistnamedcurves;
import org.ripple.bouncycastle.asn1.oiw.elgamalparameter;
import org.ripple.bouncycastle.asn1.oiw.oiwobjectidentifiers;
import org.ripple.bouncycastle.asn1.pkcs.dhparameter;
import org.ripple.bouncycastle.asn1.pkcs.pkcsobjectidentifiers;
import org.ripple.bouncycastle.asn1.pkcs.rsapublickey;
import org.ripple.bouncycastle.asn1.sec.secnamedcurves;
import org.ripple.bouncycastle.asn1.teletrust.teletrustnamedcurves;
import org.ripple.bouncycastle.asn1.x509.algorithmidentifier;
import org.ripple.bouncycastle.asn1.x509.dsaparameter;
import org.ripple.bouncycastle.asn1.x509.subjectpublickeyinfo;
import org.ripple.bouncycastle.asn1.x509.x509objectidentifiers;
import org.ripple.bouncycastle.asn1.x9.dhdomainparameters;
import org.ripple.bouncycastle.asn1.x9.dhpublickey;
import org.ripple.bouncycastle.asn1.x9.dhvalidationparms;
import org.ripple.bouncycastle.asn1.x9.x962namedcurves;
import org.ripple.bouncycastle.asn1.x9.x962parameters;
import org.ripple.bouncycastle.asn1.x9.x9ecparameters;
import org.ripple.bouncycastle.asn1.x9.x9ecpoint;
import org.ripple.bouncycastle.asn1.x9.x9objectidentifiers;
import org.ripple.bouncycastle.crypto.params.asymmetrickeyparameter;
import org.ripple.bouncycastle.crypto.params.dhparameters;
import org.ripple.bouncycastle.crypto.params.dhpublickeyparameters;
import org.ripple.bouncycastle.crypto.params.dhvalidationparameters;
import org.ripple.bouncycastle.crypto.params.dsaparameters;
import org.ripple.bouncycastle.crypto.params.dsapublickeyparameters;
import org.ripple.bouncycastle.crypto.params.ecdomainparameters;
import org.ripple.bouncycastle.crypto.params.ecpublickeyparameters;
import org.ripple.bouncycastle.crypto.params.elgamalparameters;
import org.ripple.bouncycastle.crypto.params.elgamalpublickeyparameters;
import org.ripple.bouncycastle.crypto.params.rsakeyparameters;

/**
 * factory to create asymmetric public key parameters for asymmetric ciphers from range of
 * asn.1 encoded subjectpublickeyinfo objects.
 */
public class publickeyfactory
{
    /**
     * create a public key from a subjectpublickeyinfo encoding
     * 
     * @param keyinfodata the subjectpublickeyinfo encoding
     * @return the appropriate key parameter
     * @throws ioexception on an error decoding the key
     */
    public static asymmetrickeyparameter createkey(byte[] keyinfodata) throws ioexception
    {
        return createkey(subjectpublickeyinfo.getinstance(asn1primitive.frombytearray(keyinfodata)));
    }

    /**
     * create a public key from a subjectpublickeyinfo encoding read from a stream
     * 
     * @param instr the stream to read the subjectpublickeyinfo encoding from
     * @return the appropriate key parameter
     * @throws ioexception on an error decoding the key
     */
    public static asymmetrickeyparameter createkey(inputstream instr) throws ioexception
    {
        return createkey(subjectpublickeyinfo.getinstance(new asn1inputstream(instr).readobject()));
    }

    /**
     * create a public key from the passed in subjectpublickeyinfo
     * 
     * @param keyinfo the subjectpublickeyinfo containing the key data
     * @return the appropriate key parameter
     * @throws ioexception on an error decoding the key
     */
    public static asymmetrickeyparameter createkey(subjectpublickeyinfo keyinfo) throws ioexception
    {
        algorithmidentifier algid = keyinfo.getalgorithm();

        if (algid.getalgorithm().equals(pkcsobjectidentifiers.rsaencryption)
            || algid.getalgorithm().equals(x509objectidentifiers.id_ea_rsa))
        {
            rsapublickey pubkey = rsapublickey.getinstance(keyinfo.parsepublickey());

            return new rsakeyparameters(false, pubkey.getmodulus(), pubkey.getpublicexponent());
        }
        else if (algid.getalgorithm().equals(x9objectidentifiers.dhpublicnumber))
        {
            dhpublickey dhpublickey = dhpublickey.getinstance(keyinfo.parsepublickey());

            biginteger y = dhpublickey.gety().getvalue();

            dhdomainparameters dhparams = dhdomainparameters.getinstance(algid.getparameters());

            biginteger p = dhparams.getp().getvalue();
            biginteger g = dhparams.getg().getvalue();
            biginteger q = dhparams.getq().getvalue();

            biginteger j = null;
            if (dhparams.getj() != null)
            {
                j = dhparams.getj().getvalue();
            }

            dhvalidationparameters validation = null;
            dhvalidationparms dhvalidationparms = dhparams.getvalidationparms();
            if (dhvalidationparms != null)
            {
                byte[] seed = dhvalidationparms.getseed().getbytes();
                biginteger pgencounter = dhvalidationparms.getpgencounter().getvalue();

                // todo check pgencounter size?

                validation = new dhvalidationparameters(seed, pgencounter.intvalue());
            }

            return new dhpublickeyparameters(y, new dhparameters(p, g, q, j, validation));
        }
        else if (algid.getalgorithm().equals(pkcsobjectidentifiers.dhkeyagreement))
        {
            dhparameter params = dhparameter.getinstance(algid.getparameters());
            asn1integer dery = (asn1integer)keyinfo.parsepublickey();

            biginteger lval = params.getl();
            int l = lval == null ? 0 : lval.intvalue();
            dhparameters dhparams = new dhparameters(params.getp(), params.getg(), null, l);

            return new dhpublickeyparameters(dery.getvalue(), dhparams);
        }
        else if (algid.getalgorithm().equals(oiwobjectidentifiers.elgamalalgorithm))
        {
            elgamalparameter params = new elgamalparameter((asn1sequence)algid.getparameters());
            asn1integer dery = (asn1integer)keyinfo.parsepublickey();

            return new elgamalpublickeyparameters(dery.getvalue(), new elgamalparameters(
                params.getp(), params.getg()));
        }
        else if (algid.getalgorithm().equals(x9objectidentifiers.id_dsa)
            || algid.getalgorithm().equals(oiwobjectidentifiers.dsawithsha1))
        {
            asn1integer dery = (asn1integer)keyinfo.parsepublickey();
            asn1encodable de = algid.getparameters();

            dsaparameters parameters = null;
            if (de != null)
            {
                dsaparameter params = dsaparameter.getinstance(de.toasn1primitive());
                parameters = new dsaparameters(params.getp(), params.getq(), params.getg());
            }

            return new dsapublickeyparameters(dery.getvalue(), parameters);
        }
        else if (algid.getalgorithm().equals(x9objectidentifiers.id_ecpublickey))
        {
            x962parameters params = new x962parameters(
                (asn1primitive)algid.getparameters());

            x9ecparameters x9;
            if (params.isnamedcurve())
            {
                asn1objectidentifier oid = (asn1objectidentifier)params.getparameters();
                x9 = x962namedcurves.getbyoid(oid);

                if (x9 == null)
                {
                    x9 = secnamedcurves.getbyoid(oid);

                    if (x9 == null)
                    {
                        x9 = nistnamedcurves.getbyoid(oid);

                        if (x9 == null)
                        {
                            x9 = teletrustnamedcurves.getbyoid(oid);
                        }
                    }
                }
            }
            else
            {
                x9 = x9ecparameters.getinstance(params.getparameters());
            }

            asn1octetstring key = new deroctetstring(keyinfo.getpublickeydata().getbytes());
            x9ecpoint derq = new x9ecpoint(x9.getcurve(), key);

            // todo we lose any named parameters here
            
            ecdomainparameters dparams = new ecdomainparameters(
                    x9.getcurve(), x9.getg(), x9.getn(), x9.geth(), x9.getseed());

            return new ecpublickeyparameters(derq.getpoint(), dparams);
        }
        else
        {
            throw new runtimeexception("algorithm identifier in key not recognised");
        }
    }
}
