package org.ripple.bouncycastle.jce.interfaces;

import java.util.enumeration;

import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1objectidentifier;

/**
 * allow us to set attributes on objects that can go into a pkcs12 store.
 */
public interface pkcs12bagattributecarrier
{
    void setbagattribute(
        asn1objectidentifier oid,
        asn1encodable attribute);

    asn1encodable getbagattribute(
        asn1objectidentifier oid);

    enumeration getbagattributekeys();
}
