package org.ripple.bouncycastle.asn1.x509;

import java.math.biginteger;
import java.util.enumeration;
import java.util.vector;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.dersequence;

/**
 * <code>noticereference</code> class, used in
 * <code>certificatepolicies</code> x509 v3 extensions
 * (in policy qualifiers).
 * 
 * <pre>
 *  noticereference ::= sequence {
 *      organization     displaytext,
 *      noticenumbers    sequence of integer }
 *
 * </pre> 
 * 
 * @see policyqualifierinfo
 * @see policyinformation
 */
public class noticereference 
    extends asn1object
{
    private displaytext organization;
    private asn1sequence noticenumbers;

    private static asn1encodablevector convertvector(vector numbers)
    {
        asn1encodablevector av = new asn1encodablevector();

        enumeration it = numbers.elements();

        while (it.hasmoreelements())
        {
            object o = it.nextelement();
            asn1integer di;

            if (o instanceof biginteger)
            {
                di = new asn1integer((biginteger)o);
            }
            else if (o instanceof integer)
            {
                di = new asn1integer(((integer)o).intvalue());
            }
            else
            {
                throw new illegalargumentexception();
            }

            av.add(di);
        }
        return av;
    }

   /**
    * creates a new <code>noticereference</code> instance.
    *
    * @param organization a <code>string</code> value
    * @param numbers a <code>vector</code> value
    */
   public noticereference(
       string organization,
       vector numbers) 
   {
       this(organization, convertvector(numbers));
   }

    /**
    * creates a new <code>noticereference</code> instance.
    *
    * @param organization a <code>string</code> value
    * @param noticenumbers an <code>asn1encodablevector</code> value
    */
   public noticereference(
       string organization,
       asn1encodablevector noticenumbers)
   {
       this(new displaytext(organization), noticenumbers);
   }

   /**
    * creates a new <code>noticereference</code> instance.
    *
    * @param organization displaytext
    * @param noticenumbers an <code>asn1encodablevector</code> value
    */
   public noticereference(
       displaytext  organization,
       asn1encodablevector noticenumbers)
   {
       this.organization = organization;
       this.noticenumbers = new dersequence(noticenumbers);
   }

   /**
    * creates a new <code>noticereference</code> instance.
    * <p>useful for reconstructing a <code>noticereference</code>
    * instance from its encodable/encoded form. 
    *
    * @param as an <code>asn1sequence</code> value obtained from either
    * calling @{link toasn1primitive()} for a <code>noticereference</code>
    * instance or from parsing it from a der-encoded stream. 
    */
   private noticereference(
       asn1sequence as) 
   {
       if (as.size() != 2)
       {
            throw new illegalargumentexception("bad sequence size: "
                    + as.size());
       }

       organization = displaytext.getinstance(as.getobjectat(0));
       noticenumbers = asn1sequence.getinstance(as.getobjectat(1));
   }

   public static noticereference getinstance(
       object as) 
   {
      if (as instanceof noticereference)
      {
          return (noticereference)as;
      }
      else if (as != null)
      {
          return new noticereference(asn1sequence.getinstance(as));
      }

      return null;
   }
   
   public displaytext getorganization()
   {
       return organization;
   }
   
   public asn1integer[] getnoticenumbers()
   {
       asn1integer[] tmp = new asn1integer[noticenumbers.size()];

       for (int i = 0; i != noticenumbers.size(); i++)
       {
           tmp[i] = asn1integer.getinstance(noticenumbers.getobjectat(i));
       }

       return tmp;
   }
   
   /**
    * describe <code>toasn1object</code> method here.
    *
    * @return a <code>asn1primitive</code> value
    */
   public asn1primitive toasn1primitive()
   {
      asn1encodablevector av = new asn1encodablevector();
      av.add (organization);
      av.add (noticenumbers);
      return new dersequence (av);
   }
}
