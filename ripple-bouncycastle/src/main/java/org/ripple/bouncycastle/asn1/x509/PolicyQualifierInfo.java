package org.ripple.bouncycastle.asn1.x509;

import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.deria5string;
import org.ripple.bouncycastle.asn1.dersequence;

/**
 * policy qualifiers, used in the x509v3 certificatepolicies
 * extension.
 * 
 * <pre>
 *   policyqualifierinfo ::= sequence {
 *       policyqualifierid  policyqualifierid,
 *       qualifier          any defined by policyqualifierid }
 * </pre>
 */
public class policyqualifierinfo
    extends asn1object
{
   private asn1objectidentifier policyqualifierid;
   private asn1encodable        qualifier;

   /**
    * creates a new <code>policyqualifierinfo</code> instance.
    *
    * @param policyqualifierid a <code>policyqualifierid</code> value
    * @param qualifier the qualifier, defined by the above field.
    */
   public policyqualifierinfo(
       asn1objectidentifier policyqualifierid,
       asn1encodable qualifier) 
   {
      this.policyqualifierid = policyqualifierid;
      this.qualifier = qualifier;
   }

   /**
    * creates a new <code>policyqualifierinfo</code> containing a
    * cpsuri qualifier.
    *
    * @param cps the cps (certification practice statement) uri as a
    * <code>string</code>.
    */
   public policyqualifierinfo(
       string cps) 
   {
      policyqualifierid = policyqualifierid.id_qt_cps;
      qualifier = new deria5string (cps);
   }

   /**
    * creates a new <code>policyqualifierinfo</code> instance.
    *
    * @param as <code>policyqualifierinfo</code> x509 structure
    * encoded as an asn1sequence. 
    */
   public policyqualifierinfo(
       asn1sequence as)
   {
        if (as.size() != 2)
        {
            throw new illegalargumentexception("bad sequence size: "
                    + as.size());
        }

        policyqualifierid = asn1objectidentifier.getinstance(as.getobjectat(0));
        qualifier = as.getobjectat(1);
   }

   public static policyqualifierinfo getinstance(
       object obj)
   {
        if (obj instanceof policyqualifierinfo)
        {
            return (policyqualifierinfo)obj;
        }
        else if (obj != null)
        {
            return new policyqualifierinfo(asn1sequence.getinstance(obj));
        }

        return null;
   }


   public asn1objectidentifier getpolicyqualifierid()
   {
       return policyqualifierid;
   }

   public asn1encodable getqualifier()
   {
       return qualifier;
   }
   
   /**
    * returns a der-encodable representation of this instance. 
    *
    * @return a <code>asn1primitive</code> value
    */
   public asn1primitive toasn1primitive()
   {
      asn1encodablevector dev = new asn1encodablevector();
      dev.add(policyqualifierid);
      dev.add(qualifier);

      return new dersequence(dev);
   }
}
