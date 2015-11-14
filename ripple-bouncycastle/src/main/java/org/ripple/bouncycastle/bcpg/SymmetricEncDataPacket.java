package org.ripple.bouncycastle.bcpg;

/**
 * basic type for a symmetric key encrypted packet
 */
public class symmetricencdatapacket 
    extends inputstreampacket
{
    public symmetricencdatapacket(
        bcpginputstream  in)
    {
        super(in);
    }
}
