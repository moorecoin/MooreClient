package org.ripple.bouncycastle.asn1.isismtt;

import org.ripple.bouncycastle.asn1.asn1objectidentifier;

public interface isismttobjectidentifiers
{

    static final asn1objectidentifier id_isismtt = new asn1objectidentifier("1.3.36.8");

    static final asn1objectidentifier id_isismtt_cp = id_isismtt.branch("1");

    /**
     * the id-isismtt-cp-accredited oid indicates that the certificate is a
     * qualified certificate according to directive 1999/93/ec of the european
     * parliament and of the council of 13 december 1999 on a community
     * framework for electronic signatures, which additionally conforms the
     * special requirements of the sigg and has been issued by an accredited ca.
     */
    static final asn1objectidentifier id_isismtt_cp_accredited = id_isismtt_cp.branch("1");

    static final asn1objectidentifier id_isismtt_at = id_isismtt.branch("3");

    /**
     * certificate extensiondate of certificate generation
     * 
     * <pre>
     *                dateofcertgensyntax ::= generalizedtime
     * </pre>
     */
    static final asn1objectidentifier id_isismtt_at_dateofcertgen = id_isismtt_at.branch("1");

    /**
     * attribute to indicate that the certificate holder may sign in the name of
     * a third person. may also be used as extension in a certificate.
     */
    static final asn1objectidentifier id_isismtt_at_procuration = id_isismtt_at.branch("2");

    /**
     * attribute to indicate admissions to certain professions. may be used as
     * attribute in attribute certificate or as extension in a certificate
     */
    static final asn1objectidentifier id_isismtt_at_admission = id_isismtt_at.branch("3");

    /**
     * monetary limit for transactions. the qceumonetarylimit qc statement must
     * be used in new certificates in place of the extension/attribute
     * monetarylimit since january 1, 2004. for the sake of backward
     * compatibility with certificates already in use, sigg conforming
     * components must support monetarylimit (as well as qceulimitvalue).
     */
    static final asn1objectidentifier id_isismtt_at_monetarylimit = id_isismtt_at.branch("4");

    /**
     * a declaration of majority. may be used as attribute in attribute
     * certificate or as extension in a certificate
     */
    static final asn1objectidentifier id_isismtt_at_declarationofmajority = id_isismtt_at.branch("5");

    /**
     * 
     * serial number of the smart card containing the corresponding private key
     * 
     * <pre>
     *                 iccsnsyntax ::= octet string (size(8..20))
     * </pre>
     */
    static final asn1objectidentifier id_isismtt_at_iccsn = id_isismtt_at.branch("6");

    /**
     * 
     * reference for a file of a smartcard that stores the public key of this
     * certificate and that is used as 锟絪ecurity anchor锟?
     * 
     * <pre>
     *      pkreferencesyntax ::= octet string (size(20))
     * </pre>
     */
    static final asn1objectidentifier id_isismtt_at_pkreference = id_isismtt_at.branch("7");

    /**
     * some other restriction regarding the usage of this certificate. may be
     * used as attribute in attribute certificate or as extension in a
     * certificate.
     * 
     * <pre>
     *             restrictionsyntax ::= directorystring (size(1..1024))
     * </pre>
     * 
     * @see org.ripple.bouncycastle.asn1.isismtt.x509.restriction
     */
    static final asn1objectidentifier id_isismtt_at_restriction = id_isismtt_at.branch("8");

    /**
     * 
     * (single)request extension: clients may include this extension in a
     * (single) request to request the responder to send the certificate in the
     * response message along with the status information. besides the ldap
     * service, this extension provides another mechanism for the distribution
     * of certificates, which may optionally be provided by certificate
     * repositories.
     * 
     * <pre>
     *        retrieveifallowed ::= boolean
     *       
     * </pre>
     */
    static final asn1objectidentifier id_isismtt_at_retrieveifallowed = id_isismtt_at.branch("9");

    /**
     * singleocspresponse extension: the certificate requested by the client by
     * inserting the retrieveifallowed extension in the request, will be
     * returned in this extension.
     * 
     * @see org.ripple.bouncycastle.asn1.isismtt.ocsp.requestedcertificate
     */
    static final asn1objectidentifier id_isismtt_at_requestedcertificate = id_isismtt_at.branch("10");

    /**
     * base objectidentifier for naming authorities
     */
    static final asn1objectidentifier id_isismtt_at_namingauthorities = id_isismtt_at.branch("11");

    /**
     * singleocspresponse extension: date, when certificate has been published
     * in the directory and status information has become available. currently,
     * accrediting authorities enforce that sigg-conforming ocsp servers include
     * this extension in the responses.
     * 
     * <pre>
     *      certindirsince ::= generalizedtime
     * </pre>
     */
    static final asn1objectidentifier id_isismtt_at_certindirsince = id_isismtt_at.branch("12");

    /**
     * hash of a certificate in ocsp.
     * 
     * @see org.ripple.bouncycastle.asn1.isismtt.ocsp.certhash
     */
    static final asn1objectidentifier id_isismtt_at_certhash = id_isismtt_at.branch("13");

    /**
     * <pre>
     *          nameatbirth ::= directorystring(size(1..64)
     * </pre>
     * 
     * used in
     * {@link org.ripple.bouncycastle.asn1.x509.subjectdirectoryattributes subjectdirectoryattributes}
     */
    static final asn1objectidentifier id_isismtt_at_nameatbirth = id_isismtt_at.branch("14");

    /**
     * some other information of non-restrictive nature regarding the usage of
     * this certificate. may be used as attribute in atribute certificate or as
     * extension in a certificate.
     * 
     * <pre>
     *               additionalinformationsyntax ::= directorystring (size(1..2048))
     * </pre>
     * 
     * @see org.ripple.bouncycastle.asn1.isismtt.x509.additionalinformationsyntax
     */
    static final asn1objectidentifier id_isismtt_at_additionalinformation = id_isismtt_at.branch("15");

    /**
     * indicates that an attribute certificate exists, which limits the
     * usability of this public key certificate. whenever verifying a signature
     * with the help of this certificate, the content of the corresponding
     * attribute certificate should be concerned. this extension must be
     * included in a pkc, if a corresponding attribute certificate (having the
     * pkc as base certificate) contains some attribute that restricts the
     * usability of the pkc too. attribute certificates with restricting content
     * must always be included in the signed document.
     * 
     * <pre>
     *                   liabilitylimitationflagsyntax ::= boolean
     * </pre>
     */
    static final asn1objectidentifier id_isismtt_at_liabilitylimitationflag = new asn1objectidentifier("0.2.262.1.10.12.0");
}
