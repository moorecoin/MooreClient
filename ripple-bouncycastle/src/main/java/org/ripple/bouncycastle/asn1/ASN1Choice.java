package org.ripple.bouncycastle.asn1;

/**
 * marker interface for choice objects - if you implement this in a role your
 * own object any attempt to tag the object implicitly will convert the tag to
 * an explicit one as the encoding rules require.
 * <p>
 * if you use this interface your class should also implement the getinstance
 * pattern which takes a tag object and the tagging mode used. 
 */
public interface asn1choice
{
    // marker interface
}
