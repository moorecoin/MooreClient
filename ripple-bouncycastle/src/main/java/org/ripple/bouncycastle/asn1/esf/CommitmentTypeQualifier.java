package org.ripple.bouncycastle.asn1.esf;

import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.dersequence;

/**
 * commitment type qualifiers, used in the commitment-type-indication attribute (rfc3126).
 * 
 * <pre>
 *   commitmenttypequalifier ::= sequence {
 *       commitmenttypeidentifier  commitmenttypeidentifier,
 *       qualifier          any defined by commitmenttypeidentifier optional }
 * </pre>
 */
public class commitmenttypequalifier
    extends asn1object
{
   private asn1objectidentifier commitmenttypeidentifier;
   private asn1encodable qualifier;

   /**
    * creates a new <code>commitmenttypequalifier</code> instance.
    *
    * @param commitmenttypeidentifier a <code>commitmenttypeidentifier</code> value
    */
    public commitmenttypequalifier(
        asn1objectidentifier commitmenttypeidentifier)
    {
        this(commitmenttypeidentifier, null);
    }
    
   /**
    * creates a new <code>commitmenttypequalifier</code> instance.
    *
    * @param commitmenttypeidentifier a <code>commitmenttypeidentifier</code> value
    * @param qualifier the qualifier, defined by the above field.
    */
    public commitmenttypequalifier(
        asn1objectidentifier commitmenttypeidentifier,
        asn1encodable qualifier)
    {
        this.commitmenttypeidentifier = commitmenttypeidentifier;
        this.qualifier = qualifier;
    }

    /**
     * creates a new <code>commitmenttypequalifier</code> instance.
     *
     * @param as <code>commitmenttypequalifier</code> structure
     * encoded as an asn1sequence. 
     */
    private commitmenttypequalifier(
        asn1sequence as)
    {
        commitmenttypeidentifier = (asn1objectidentifier)as.getobjectat(0);
        
        if (as.size() > 1)
        {
            qualifier = as.getobjectat(1);
        }
    }

    public static commitmenttypequalifier getinstance(object as)
    {
        if (as instanceof commitmenttypequalifier)
        {
            return (commitmenttypequalifier)as;
        }
        else if (as != null)
        {
            return new commitmenttypequalifier(asn1sequence.getinstance(as));
        }

        return null;
    }

    public asn1objectidentifier getcommitmenttypeidentifier()
    {
        return commitmenttypeidentifier;
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
      dev.add(commitmenttypeidentifier);
      if (qualifier != null)
      {
          dev.add(qualifier);
      }

      return new dersequence(dev);
   }
}
