package org.ripple.bouncycastle.jce.interfaces;

/**
 * all bc elliptic curve keys implement this interface. you need to
 * cast the key to get access to it.
 * <p>
 * by default bc keys produce encodings without point compression,
 * to turn this on call setpointformat() with "compressed".
 */
public interface ecpointencoder
{
    /**
     * set the formatting for encoding of points. if the string "uncompressed" is passed
     * in point compression will not be used. if the string "compressed" is passed point
     * compression will be used. the default is "uncompressed".
     * 
     * @param style the style to use.
     */
    public void setpointformat(string style);
}
