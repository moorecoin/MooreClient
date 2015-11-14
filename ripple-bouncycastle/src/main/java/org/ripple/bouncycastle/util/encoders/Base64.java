package org.ripple.bouncycastle.util.encoders;

import java.io.bytearrayoutputstream;
import java.io.ioexception;
import java.io.outputstream;

import org.ripple.bouncycastle.util.strings;

public class base64
{
    private static final encoder encoder = new base64encoder();
    
    public static string tobase64string(
        byte[] data)
    {
        return tobase64string(data, 0, data.length);
    }

    public static string tobase64string(
        byte[] data,
        int    off,
        int    length)
    {
        byte[] encoded = encode(data, off, length);
        return strings.frombytearray(encoded);
    }

    /**
     * encode the input data producing a base 64 encoded byte array.
     *
     * @return a byte array containing the base 64 encoded data.
     */
    public static byte[] encode(
        byte[]    data)
    {
        return encode(data, 0, data.length);
    }

    /**
     * encode the input data producing a base 64 encoded byte array.
     *
     * @return a byte array containing the base 64 encoded data.
     */
    public static byte[] encode(
        byte[] data,
        int    off,
        int    length)
    {
        int len = (length + 2) / 3 * 4;
        bytearrayoutputstream bout = new bytearrayoutputstream(len);

        try
        {
            encoder.encode(data, off, length, bout);
        }
        catch (exception e)
        {
            throw new encoderexception("exception encoding base64 string: " + e.getmessage(), e);
        }
        
        return bout.tobytearray();
    }

    /**
     * encode the byte data to base 64 writing it to the given output stream.
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
     * encode the byte data to base 64 writing it to the given output stream.
     *
     * @return the number of bytes produced.
     */
    public static int encode(
        byte[]                data,
        int                    off,
        int                    length,
        outputstream    out)
        throws ioexception
    {
        return encoder.encode(data, off, length, out);
    }
    
    /**
     * decode the base 64 encoded input data. it is assumed the input data is valid.
     *
     * @return a byte array representing the decoded data.
     */
    public static byte[] decode(
        byte[]    data)
    {
        int len = data.length / 4 * 3;
        bytearrayoutputstream bout = new bytearrayoutputstream(len);
        
        try
        {
            encoder.decode(data, 0, data.length, bout);
        }
        catch (exception e)
        {
            throw new decoderexception("unable to decode base64 data: " + e.getmessage(), e);
        }
        
        return bout.tobytearray();
    }
    
    /**
     * decode the base 64 encoded string data - whitespace will be ignored.
     *
     * @return a byte array representing the decoded data.
     */
    public static byte[] decode(
        string    data)
    {
        int len = data.length() / 4 * 3;
        bytearrayoutputstream bout = new bytearrayoutputstream(len);
        
        try
        {
            encoder.decode(data, bout);
        }
        catch (exception e)
        {
            throw new decoderexception("unable to decode base64 string: " + e.getmessage(), e);
        }
        
        return bout.tobytearray();
    }
    
    /**
     * decode the base 64 encoded string data writing it to the given output stream,
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
