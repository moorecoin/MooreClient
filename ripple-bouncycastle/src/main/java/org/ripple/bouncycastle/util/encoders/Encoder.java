package org.ripple.bouncycastle.util.encoders;

import java.io.ioexception;
import java.io.outputstream;

/**
 * encode and decode byte arrays (typically from binary to 7-bit ascii 
 * encodings).
 */
public interface encoder
{
    int encode(byte[] data, int off, int length, outputstream out) throws ioexception;
    
    int decode(byte[] data, int off, int length, outputstream out) throws ioexception;

    int decode(string data, outputstream out) throws ioexception;
}
