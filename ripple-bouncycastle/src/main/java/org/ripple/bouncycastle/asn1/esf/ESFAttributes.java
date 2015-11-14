package org.ripple.bouncycastle.asn1.esf;

import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.pkcs.pkcsobjectidentifiers;

public interface esfattributes
{
    public static final asn1objectidentifier  sigpolicyid = pkcsobjectidentifiers.id_aa_ets_sigpolicyid;
    public static final asn1objectidentifier  commitmenttype = pkcsobjectidentifiers.id_aa_ets_commitmenttype;
    public static final asn1objectidentifier  signerlocation = pkcsobjectidentifiers.id_aa_ets_signerlocation;
    public static final asn1objectidentifier  signerattr = pkcsobjectidentifiers.id_aa_ets_signerattr;
    public static final asn1objectidentifier  othersigcert = pkcsobjectidentifiers.id_aa_ets_othersigcert;
    public static final asn1objectidentifier  contenttimestamp = pkcsobjectidentifiers.id_aa_ets_contenttimestamp;
    public static final asn1objectidentifier  certificaterefs = pkcsobjectidentifiers.id_aa_ets_certificaterefs;
    public static final asn1objectidentifier  revocationrefs = pkcsobjectidentifiers.id_aa_ets_revocationrefs;
    public static final asn1objectidentifier  certvalues = pkcsobjectidentifiers.id_aa_ets_certvalues;
    public static final asn1objectidentifier  revocationvalues = pkcsobjectidentifiers.id_aa_ets_revocationvalues;
    public static final asn1objectidentifier  esctimestamp = pkcsobjectidentifiers.id_aa_ets_esctimestamp;
    public static final asn1objectidentifier  certcrltimestamp = pkcsobjectidentifiers.id_aa_ets_certcrltimestamp;
    public static final asn1objectidentifier  archivetimestamp = pkcsobjectidentifiers.id_aa_ets_archivetimestamp;
    public static final asn1objectidentifier  archivetimestampv2 = pkcsobjectidentifiers.id_aa.branch("48");
}
