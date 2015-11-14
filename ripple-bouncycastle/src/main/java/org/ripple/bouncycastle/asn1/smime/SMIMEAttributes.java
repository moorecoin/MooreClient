package org.ripple.bouncycastle.asn1.smime;

import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.pkcs.pkcsobjectidentifiers;

public interface smimeattributes
{
    public static final asn1objectidentifier  smimecapabilities = pkcsobjectidentifiers.pkcs_9_at_smimecapabilities;
    public static final asn1objectidentifier  encrypkeypref = pkcsobjectidentifiers.id_aa_encrypkeypref;
}
