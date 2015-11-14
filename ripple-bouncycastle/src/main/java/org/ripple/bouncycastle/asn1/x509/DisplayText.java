
package org.ripple.bouncycastle.asn1.x509;

import org.ripple.bouncycastle.asn1.asn1choice;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1string;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.derbmpstring;
import org.ripple.bouncycastle.asn1.deria5string;
import org.ripple.bouncycastle.asn1.derutf8string;
import org.ripple.bouncycastle.asn1.dervisiblestring;

/**
 * <code>displaytext</code> class, used in
 * <code>certificatepolicies</code> x509 v3 extensions (in policy qualifiers).
 *
 * <p>it stores a string in a chosen encoding. 
 * <pre>
 * displaytext ::= choice {
 *      ia5string        ia5string      (size (1..200)),
 *      visiblestring    visiblestring  (size (1..200)),
 *      bmpstring        bmpstring      (size (1..200)),
 *      utf8string       utf8string     (size (1..200)) }
 * </pre>
 * @see policyqualifierinfo
 * @see policyinformation
 */
public class displaytext 
    extends asn1object
    implements asn1choice
{
   /**
    * constant corresponding to ia5string encoding. 
    *
    */
   public static final int content_type_ia5string = 0;
   /**
    * constant corresponding to bmpstring encoding. 
    *
    */
   public static final int content_type_bmpstring = 1;
   /**
    * constant corresponding to utf8string encoding. 
    *
    */
   public static final int content_type_utf8string = 2;
   /**
    * constant corresponding to visiblestring encoding. 
    *
    */
   public static final int content_type_visiblestring = 3;

   /**
    * describe constant <code>display_text_maximum_size</code> here.
    *
    */
   public static final int display_text_maximum_size = 200;
   
   int contenttype;
   asn1string contents;
   
   /**
    * creates a new <code>displaytext</code> instance.
    *
    * @param type the desired encoding type for the text. 
    * @param text the text to store. strings longer than 200
    * characters are truncated. 
    */
   public displaytext(int type, string text)
   {
      if (text.length() > display_text_maximum_size)
      {
         // rfc3280 limits these strings to 200 chars
         // truncate the string
         text = text.substring (0, display_text_maximum_size);
      }
     
      contenttype = type;
      switch (type)
      {
         case content_type_ia5string:
            contents = new deria5string(text);
            break;
         case content_type_utf8string:
            contents = new derutf8string(text);
            break;
         case content_type_visiblestring:
            contents = new dervisiblestring(text);
            break;
         case content_type_bmpstring:
            contents = new derbmpstring(text);
            break;
         default:
            contents = new derutf8string(text);
            break;
      }
   }
   
   /**
    * creates a new <code>displaytext</code> instance.
    *
    * @param text the text to encapsulate. strings longer than 200
    * characters are truncated. 
    */
   public displaytext(string text) 
   {
      // by default use utf8string
      if (text.length() > display_text_maximum_size)
      {
         text = text.substring(0, display_text_maximum_size);
      }
      
      contenttype = content_type_utf8string;
      contents = new derutf8string(text);
   }

   /**
    * creates a new <code>displaytext</code> instance.
    * <p>useful when reading back a <code>displaytext</code> class
    * from it's asn1encodable/derencodable form. 
    *
    * @param de a <code>derencodable</code> instance. 
    */
   private displaytext(asn1string de)
   {
      contents = de;
   }

   public static displaytext getinstance(object obj) 
   {
      if  (obj instanceof asn1string)
      {
          return new displaytext((asn1string)obj);
      }
      else if (obj == null || obj instanceof displaytext)
      {
          return (displaytext)obj;
      }

      throw new illegalargumentexception("illegal object in getinstance: " + obj.getclass().getname());
   }

   public static displaytext getinstance(
       asn1taggedobject obj,
       boolean          explicit)
   {
       return getinstance(obj.getobject()); // must be explicitly tagged
   }
   
   public asn1primitive toasn1primitive()
   {
      return (asn1primitive)contents;
   }

   /**
    * returns the stored <code>string</code> object. 
    *
    * @return the stored text as a <code>string</code>. 
    */
   public string getstring() 
   {
      return contents.getstring();
   }   
}
