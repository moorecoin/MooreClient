package org.ripple.bouncycastle.util.encoders;

/**
 * convert binary data to and from urlbase64 encoding.  this is identical to
 * base64 encoding, except that the padding character is "." and the other 
 * non-alphanumeric characters are "-" and "_" instead of "+" and "/".
 * <p>
 * the purpose of urlbase64 encoding is to provide a compact encoding of binary
 * data that is safe for use as an url parameter. base64 encoding does not
 * produce encoded values that are safe for use in urls, since "/" can be 
 * interpreted as a path delimiter; "+" is the encoded form of a space; and
 * "=" is used to separate a name from the corresponding value in an url 
 * parameter.
 */
public class urlbase64encoder extends base64encoder
{
    public urlbase64encoder()
    {
        encodingtable[encodingtable.length - 2] = (byte) '-';
        encodingtable[encodingtable.length - 1] = (byte) '_';
        padding = (byte) '.';
        // we must re-create the decoding table with the new encoded values.
        initialisedecodingtable();
    }
}
