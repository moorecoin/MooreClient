package org.ripple.bouncycastle.asn1.cmp;

import org.ripple.bouncycastle.asn1.derbitstring;

/**
 * <pre>
 * pkifailureinfo ::= bit string {
 * badalg               (0),
 *   -- unrecognized or unsupported algorithm identifier
 * badmessagecheck      (1), -- integrity check failed (e.g., signature did not verify)
 * badrequest           (2),
 *   -- transaction not permitted or supported
 * badtime              (3), -- messagetime was not sufficiently close to the system time, as defined by local policy
 * badcertid            (4), -- no certificate could be found matching the provided criteria
 * baddataformat        (5),
 *   -- the data submitted has the wrong format
 * wrongauthority       (6), -- the authority indicated in the request is different from the one creating the response token
 * incorrectdata        (7), -- the requester's data is incorrect (for notary services)
 * missingtimestamp     (8), -- when the timestamp is missing but should be there (by policy)
 * badpop               (9)  -- the proof-of-possession failed
 * certrevoked         (10),
 * certconfirmed       (11),
 * wrongintegrity      (12),
 * badrecipientnonce   (13), 
 * timenotavailable    (14),
 *   -- the tsa's time source is not available
 * unacceptedpolicy    (15),
 *   -- the requested tsa policy is not supported by the tsa
 * unacceptedextension (16),
 *   -- the requested extension is not supported by the tsa
 * addinfonotavailable (17)
 *   -- the additional information requested could not be understood
 *   -- or is not available
 * badsendernonce      (18),
 * badcerttemplate     (19),
 * signernottrusted    (20),
 * transactionidinuse  (21),
 * unsupportedversion  (22),
 * notauthorized       (23),
 * systemunavail       (24),    
 * systemfailure       (25),
 *   -- the request cannot be handled due to system failure
 * duplicatecertreq    (26) 
 * </pre>
 */
public class pkifailureinfo
    extends derbitstring
{
    public static final int badalg               = (1 << 7); // unrecognized or unsupported algorithm identifier
    public static final int badmessagecheck      = (1 << 6); // integrity check failed (e.g., signature did not verify)
    public static final int badrequest           = (1 << 5);
    public static final int badtime              = (1 << 4); // -- messagetime was not sufficiently close to the system time, as defined by local policy
    public static final int badcertid            = (1 << 3); // no certificate could be found matching the provided criteria
    public static final int baddataformat        = (1 << 2);
    public static final int wrongauthority       = (1 << 1); // the authority indicated in the request is different from the one creating the response token
    public static final int incorrectdata        = 1;        // the requester's data is incorrect (for notary services)
    public static final int missingtimestamp     = (1 << 15); // when the timestamp is missing but should be there (by policy)
    public static final int badpop               = (1 << 14); // the proof-of-possession failed
    public static final int certrevoked          = (1 << 13);
    public static final int certconfirmed        = (1 << 12);
    public static final int wrongintegrity       = (1 << 11);
    public static final int badrecipientnonce    = (1 << 10);
    public static final int timenotavailable     = (1 << 9); // the tsa's time source is not available
    public static final int unacceptedpolicy     = (1 << 8); // the requested tsa policy is not supported by the tsa
    public static final int unacceptedextension  = (1 << 23); //the requested extension is not supported by the tsa
    public static final int addinfonotavailable  = (1 << 22); //the additional information requested could not be understood or is not available
    public static final int badsendernonce       = (1 << 21);
    public static final int badcerttemplate      = (1 << 20);
    public static final int signernottrusted     = (1 << 19);
    public static final int transactionidinuse   = (1 << 18);
    public static final int unsupportedversion   = (1 << 17);
    public static final int notauthorized        = (1 << 16);
    public static final int systemunavail        = (1 << 31);
    public static final int systemfailure        = (1 << 30); //the request cannot be handled due to system failure
    public static final int duplicatecertreq     = (1 << 29);

    /** @deprecated use lower case version */
    public static final int bad_alg                   = badalg; // unrecognized or unsupported algorithm identifier
    /** @deprecated use lower case version */
    public static final int bad_message_check         = badmessagecheck;
    /** @deprecated use lower case version */
    public static final int bad_request               = badrequest; // transaction not permitted or supported
    /** @deprecated use lower case version */
    public static final int bad_time                  = badtime;
    /** @deprecated use lower case version */
    public static final int bad_cert_id               = badcertid;
    /** @deprecated use lower case version */
    public static final int bad_data_format           = baddataformat; // the data submitted has the wrong format
    /** @deprecated use lower case version */
    public static final int wrong_authority           = wrongauthority;
    /** @deprecated use lower case version */
    public static final int incorrect_data            = incorrectdata;
    /** @deprecated use lower case version */
    public static final int missing_time_stamp        = missingtimestamp;
    /** @deprecated use lower case version */
    public static final int bad_pop                   = badpop;
    /** @deprecated use lower case version */
    public static final int time_not_available        = timenotavailable;
    /** @deprecated use lower case version */
    public static final int unaccepted_policy         = unacceptedpolicy;
    /** @deprecated use lower case version */
    public static final int unaccepted_extension      = unacceptedextension;
    /** @deprecated use lower case version */
    public static final int add_info_not_available    = addinfonotavailable; 
    /** @deprecated use lower case version */
    public static final int system_failure            = systemfailure; 
    /**
     * basic constructor.
     */
    public pkifailureinfo(
        int info)
    {
        super(getbytes(info), getpadbits(info));
    }

    public pkifailureinfo(
        derbitstring info)
    {
        super(info.getbytes(), info.getpadbits());
    }
    
    public string tostring()
    {
        return "pkifailureinfo: 0x" + integer.tohexstring(this.intvalue());
    }
}
