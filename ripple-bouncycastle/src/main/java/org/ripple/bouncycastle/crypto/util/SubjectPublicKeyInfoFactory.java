package org.ripple.bouncycastle.crypto.util;

import java.io.ioexception;

import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1octetstring;
import org.ripple.bouncycastle.asn1.dernull;
import org.ripple.bouncycastle.asn1.pkcs.pkcsobjectidentifiers;
import org.ripple.bouncycastle.asn1.pkcs.rsapublickey;
import org.ripple.bouncycastle.asn1.x509.algorithmidentifier;
import org.ripple.bouncycastle.asn1.x509.subjectpublickeyinfo;
import org.ripple.bouncycastle.asn1.x9.x962parameters;
import org.ripple.bouncycastle.asn1.x9.x9ecparameters;
import org.ripple.bouncycastle.asn1.x9.x9ecpoint;
import org.ripple.bouncycastle.asn1.x9.x9objectidentifiers;
import org.ripple.bouncycastle.crypto.params.asymmetrickeyparameter;
import org.ripple.bouncycastle.crypto.params.dsapublickeyparameters;
import org.ripple.bouncycastle.crypto.params.ecdomainparameters;
import org.ripple.bouncycastle.crypto.params.ecpublickeyparameters;
import org.ripple.bouncycastle.crypto.params.rsakeyparameters;

/**
 * factory to create asn.1 subject public key info objects from lightweight public keys.
 */
public class subjectpublickeyinfofactory
{
    /**
     * create a subjectpublickeyinfo public key.
     *
     * @param publickey the subjectpublickeyinfo encoding
     * @return the appropriate key parameter
     * @throws java.io.ioexception on an error encoding the key
     */
    public static subjectpublickeyinfo createsubjectpublickeyinfo(asymmetrickeyparameter publickey) throws ioexception
    {
        if (publickey instanceof rsakeyparameters)
        {
            rsakeyparameters pub = (rsakeyparameters)publickey;

            return new subjectpublickeyinfo(new algorithmidentifier(pkcsobjectidentifiers.rsaencryption, dernull.instance), new rsapublickey(pub.getmodulus(), pub.getexponent()));
        }
        else if (publickey instanceof dsapublickeyparameters)
        {
            dsapublickeyparameters pub = (dsapublickeyparameters)publickey;

            return new subjectpublickeyinfo(new algorithmidentifier(x9objectidentifiers.id_dsa), new asn1integer(pub.gety()));
        }
        else if (publickey instanceof ecpublickeyparameters)
        {
            ecpublickeyparameters pub = (ecpublickeyparameters)publickey;
            ecdomainparameters domainparams = pub.getparameters();
            asn1encodable      params;

            // todo: need to handle named curves
            if (domainparams == null)
            {
                params = new x962parameters(dernull.instance);      // implicitly ca
            }
            else
            {
                x9ecparameters ecp = new x9ecparameters(
                    domainparams.getcurve(),
                    domainparams.getg(),
                    domainparams.getn(),
                    domainparams.geth(),
                    domainparams.getseed());

                params = new x962parameters(ecp);
            }

            asn1octetstring p = (asn1octetstring)new x9ecpoint(pub.getq()).toasn1primitive();

            return new subjectpublickeyinfo(new algorithmidentifier(x9objectidentifiers.id_ecpublickey, params), p.getoctets());
        }
        else
        {
            throw new ioexception("key parameters not recognised.");
        }
    }
}
