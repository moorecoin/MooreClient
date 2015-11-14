package org.ripple.bouncycastle.asn1.esf;

import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.pkcs.pkcsobjectidentifiers;

public interface commitmenttypeidentifier
{
    public static final asn1objectidentifier proofoforigin = pkcsobjectidentifiers.id_cti_ets_proofoforigin;
    public static final asn1objectidentifier proofofreceipt = pkcsobjectidentifiers.id_cti_ets_proofofreceipt;
    public static final asn1objectidentifier proofofdelivery = pkcsobjectidentifiers.id_cti_ets_proofofdelivery;
    public static final asn1objectidentifier proofofsender = pkcsobjectidentifiers.id_cti_ets_proofofsender;
    public static final asn1objectidentifier proofofapproval = pkcsobjectidentifiers.id_cti_ets_proofofapproval;
    public static final asn1objectidentifier proofofcreation = pkcsobjectidentifiers.id_cti_ets_proofofcreation;
}
