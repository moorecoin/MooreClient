package org.ripple.bouncycastle.util.encoders;

import java.io.bytearrayoutputstream;
import java.io.ioexception;
import java.io.outputstream;

import org.ripple.bouncycastle.util.strings;

public class hex
{
    private static final encoder encoder = new hexencoder();
    
    public static string tohexstring(
        byte[] data)
    {
        return tohexstring(data, 0, data.length);
    }

    public static string tohexstring(
        byte[] data,
        int    off,
        int    length)
    {
        byte[] encoded = encode(data, off, length);
        return strings.frombytearray(encoded);
    }

    /**
     * encode the input data producing a hex encoded byte array.
     *
     * @return a byte array containing the hex encoded data.
     */
    public static byte[] encode(
        byte[]    data)
    {
        return encode(data, 0, data.length);
    }
    
    /**
     * encode the input data producing a hex encoded byte array.
     *
     * @return a byte array containing the hex encoded data.
     */
    public static byte[] encode(
        byte[]    data,
        int       off,
        int       length)
    {
        bytearrayoutputstream    bout = new bytearrayoutputstream();
        
        try
        {
            encoder.encode(data, off, length, bout);
        }
        catch (exception e)
        {
            throw new encoderexception("exception encoding hex string: " + e.getmessage(), e);
        }
        
        return bout.tobytearray();
    }

    /**
     * hex encode the byte data writing it to the given output stream.
     *
     * @return the number of bytes produced.
     */
    public static int encode(
        byte[]         data,
        outputstream   out)
        throws ioexception
    {
        return encoder.encode(data, 0, data.length, out);
    }
    
    /**
     * hex encode the byte data writing it to the given output stream.
     *
     * @return the number of bytes produced.
     */
    public static int encode(
        byte[]         data,
        int            off,
        int            length,
        outputstream   out)
        throws ioexception
    {
        return encoder.encode(data, off, length, out);
    }
    
    /**
     * decode the hex encoded input data. it is assumed the input data is valid.
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
            throw new decoderexception("exception decoding hex data: " + e.getmessage(), e);
        }
        
        return bout.tobytearray();
    }
    
    /**
     * decode the hex encoded string data - whitespace will be ignored.
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
            throw new decoderexception("exception decoding hex string: " + e.getmessage(), e);
        }
        
        return bout.tobytearray();
    }
    
    /**
     * decode the hex encoded string data writing it to the given output stream,
     * whitespace characters will be ignored.
     *
     * @return the number of bytes produced.
     */
    public static int decode(
        string          data,
        outputstream    out)
        throws ioexception
    {
        return encoder.decode(data, out);
    }
}
