package org.ripple.bouncycastle.asn1.cms;

import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.pkcs.pkcsobjectidentifiers;

public interface cmsattributes
{
    public static final asn1objectidentifier  contenttype = pkcsobjectidentifiers.pkcs_9_at_contenttype;
    public static final asn1objectidentifier  messagedigest = pkcsobjectidentifiers.pkcs_9_at_messagedigest;
    public static final asn1objectidentifier  signingtime = pkcsobjectidentifiers.pkcs_9_at_signingtime;
    public static final asn1objectidentifier  countersignature = pkcsobjectidentifiers.pkcs_9_at_countersignature;
    public static final asn1objectidentifier  contenthint = pkcsobjectidentifiers.id_aa_contenthint;
}
