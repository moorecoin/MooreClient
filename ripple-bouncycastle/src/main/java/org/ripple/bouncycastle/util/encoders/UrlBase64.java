package org.ripple.bouncycastle.util.encoders;

import java.io.bytearrayoutputstream;
import java.io.ioexception;
import java.io.outputstream;

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
public class urlbase64
{
    private static final encoder encoder = new urlbase64encoder();
    
    /**
     * encode the input data producing a url safe base 64 encoded byte array.
     *
     * @return a byte array containing the url safe base 64 encoded data.
     */
    public static byte[] encode(
        byte[]    data)
    {
        bytearrayoutputstream    bout = new bytearrayoutputstream();
        
        try
        {
            encoder.encode(data, 0, data.length, bout);
        }
        catch (exception e)
        {
            throw new encoderexception("exception encoding url safe base64 data: " + e.getmessage(), e);
        }
        
        return bout.tobytearray();
    }

    /**
     * encode the byte data writing it to the given output stream.
     *
     * @return the number of bytes produced.
     */
    public static int encode(
        byte[]                data,
        outputstream    out)
        throws ioexception
    {
        return encoder.encode(data, 0, data.length, out);
    }
    
    /**
     * decode the url safe base 64 encoded input data - white space will be ignored.
     *
     * @return a byte array representing the decoded data.
     */
    public static byte[] decode(
        byte[]    data)
    {
        bytearrayoutputstream    bout = new bytearrayoutputstream();
        
        try
        {
            encoder.decode(data, 0, data.length, bout);
        }
        catch (exception e)
        {
            throw new decoderexception("exception decoding url safe base64 string: " + e.getmessage(), e);
        }
        
        return bout.tobytearray();
    }
    
    /**
     * decode the url safe base 64 encoded byte data writing it to the given output stream,
     * whitespace characters will be ignored.
     *
     * @return the number of bytes produced.
     */
    public static int decode(
        byte[]                data,
        outputstream    out)
        throws ioexception
    {
        return encoder.decode(data, 0, data.length, out);
    }
    
    /**
     * decode the url safe base 64 encoded string data - whitespace will be ignored.
     *
     * @return a byte array representing the decoded data.
     */
    public static byte[] decode(
        string    data)
    {
        bytearrayoutputstream    bout = new bytearrayoutputstream();
        
        try
        {
            encoder.decode(data, bout);
        }
        catch (exception e)
        {
            throw new decoderexception("exception decoding url safe base64 string: " + e.getmessage(), e);
        }
        
        return bout.tobytearray();
    }
    
    /**
     * decode the url safe base 64 encoded string data writing it to the given output stream,
     * whitespace characters will be ignored.
     *
     * @return the number of bytes produced.
     */
    public static int decode(
        string                data,
        outputstream    out)
        throws ioexception
    {
        return encoder.decode(data, out);
    }
}
