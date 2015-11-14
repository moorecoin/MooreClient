package org.ripple.bouncycastle.ocsp;

import java.io.ioexception;

import org.ripple.bouncycastle.asn1.asn1octetstring;
import org.ripple.bouncycastle.asn1.deroctetstring;
import org.ripple.bouncycastle.asn1.ocsp.ocspobjectidentifiers;
import org.ripple.bouncycastle.asn1.ocsp.ocspresponse;
import org.ripple.bouncycastle.asn1.ocsp.ocspresponsestatus;
import org.ripple.bouncycastle.asn1.ocsp.responsebytes;

/**
 * base generator for an ocsp response - at the moment this only supports the
 * generation of responses containing basicocsp responses.
 *
 * @deprecated use classes in org.bouncycastle.cert.ocsp.
 */
public class ocsprespgenerator
{
    public static final int successful            = 0;  // response has valid confirmations
    public static final int malformed_request     = 1;  // illegal confirmation request
    public static final int internal_error        = 2;  // internal error in issuer
    public static final int try_later             = 3;  // try again later
                                                        // (4) is not used
    public static final int sig_required          = 5;  // must sign the request
    public static final int unauthorized          = 6;  // request unauthorized

    public ocspresp generate(
        int     status,
        object  response)
        throws ocspexception
    {
      if (response == null)
      {
              return new ocspresp(new ocspresponse(new ocspresponsestatus(status),null));
      }
        if (response instanceof basicocspresp)
        {
            basicocspresp   r = (basicocspresp)response;
            asn1octetstring octs;
            
            try
            {
                octs = new deroctetstring(r.getencoded());
            }
            catch (ioexception e)
            {
                throw new ocspexception("can't encode object.", e);
            }

            responsebytes   rb = new responsebytes(
                    ocspobjectidentifiers.id_pkix_ocsp_basic, octs);

            return new ocspresp(new ocspresponse(
                                    new ocspresponsestatus(status), rb));
        }

        throw new ocspexception("unknown response object");
    }
}
