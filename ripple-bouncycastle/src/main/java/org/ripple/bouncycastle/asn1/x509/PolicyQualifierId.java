
package org.ripple.bouncycastle.asn1.x509;

import org.ripple.bouncycastle.asn1.asn1objectidentifier;

/**
 * policyqualifierid, used in the certificatepolicies
 * x509v3 extension.
 * 
 * <pre>
 *    id-qt          object identifier ::=  { id-pkix 2 }
 *    id-qt-cps      object identifier ::=  { id-qt 1 }
 *    id-qt-unotice  object identifier ::=  { id-qt 2 }
 *  policyqualifierid ::=
 *       object identifier (id-qt-cps | id-qt-unotice)
 * </pre>
 */
public class policyqualifierid extends asn1objectidentifier 
{
   private static final string id_qt = "1.3.6.1.5.5.7.2";

   private policyqualifierid(string id) 
      {
         super(id);
      }
   
   public static final policyqualifierid id_qt_cps =
       new policyqualifierid(id_qt + ".1");
   public static final policyqualifierid id_qt_unotice =
       new policyqualifierid(id_qt + ".2");
}
