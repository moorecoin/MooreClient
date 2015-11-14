package org.ripple.bouncycastle.crypto.tls;

/**
 * rfc 5246 7.2.
 */
public class alertdescription
{

    /**
     * this message notifies the recipient that the sender will not send any more messages on this
     * connection. the session becomes unresumable if any connection is terminated without proper
     * close_notify messages with level equal to warning.
     */
    public static final short close_notify = 0;

    /**
     * an inappropriate message was received. this alert is always fatal and should never be
     * observed in communication between proper implementations.
     */
    public static final short unexpected_message = 10;

    /**
     * this alert is returned if a record is received with an incorrect mac. this alert also must be
     * returned if an alert is sent because a tlsciphertext decrypted in an invalid way: either it
     * wasn't an even multiple of the block length, or its padding values, when checked, weren't
     * correct. this message is always fatal and should never be observed in communication between
     * proper implementations (except when messages were corrupted in the network).
     */
    public static final short bad_record_mac = 20;

    /**
     * this alert was used in some earlier versions of tls, and may have permitted certain attacks
     * against the cbc mode [cbcatt]. it must not be sent by compliant implementations.
     */
    public static final short decryption_failed = 21;

    /**
     * a tlsciphertext record was received that had a length more than 2^14+2048 bytes, or a record
     * decrypted to a tlscompressed record with more than 2^14+1024 bytes. this message is always
     * fatal and should never be observed in communication between proper implementations (except
     * when messages were corrupted in the network).
     */
    public static final short record_overflow = 22;

    /**
     * the decompression function received improper input (e.g., data that would expand to excessive
     * length). this message is always fatal and should never be observed in communication between
     * proper implementations.
     */
    public static final short decompression_failure = 30;

    /**
     * reception of a handshake_failure alert message indicates that the sender was unable to
     * negotiate an acceptable set of security parameters given the options available. this is a
     * fatal error.
     */
    public static final short handshake_failure = 40;

    /**
     * this alert was used in sslv3 but not any version of tls. it must not be sent by compliant
     * implementations.
     */
    public static final short no_certificate = 41;

    /**
     * a certificate was corrupt, contained signatures that did not verify correctly, etc.
     */
    public static final short bad_certificate = 42;

    /**
     * a certificate was of an unsupported type.
     */
    public static final short unsupported_certificate = 43;

    /**
     * a certificate was revoked by its signer.
     */
    public static final short certificate_revoked = 44;

    /**
     * a certificate has expired or is not currently valid.
     */
    public static final short certificate_expired = 45;

    /**
     * some other (unspecified) issue arose in processing the certificate, rendering it
     * unacceptable.
     */
    public static final short certificate_unknown = 46;

    /**
     * a field in the handshake was out of range or inconsistent with other fields. this message is
     * always fatal.
     */
    public static final short illegal_parameter = 47;

    /**
     * a valid certificate chain or partial chain was received, but the certificate was not accepted
     * because the ca certificate could not be located or couldn't be matched with a known, trusted
     * ca. this message is always fatal.
     */
    public static final short unknown_ca = 48;

    /**
     * a valid certificate was received, but when access control was applied, the sender decided not
     * to proceed with negotiation. this message is always fatal.
     */
    public static final short access_denied = 49;

    /**
     * a message could not be decoded because some field was out of the specified range or the
     * length of the message was incorrect. this message is always fatal and should never be
     * observed in communication between proper implementations (except when messages were corrupted
     * in the network).
     */
    public static final short decode_error = 50;

    /**
     * a handshake cryptographic operation failed, including being unable to correctly verify a
     * signature or validate a finished message. this message is always fatal.
     */
    public static final short decrypt_error = 51;

    /**
     * this alert was used in some earlier versions of tls. it must not be sent by compliant
     * implementations.
     */
    public static final short export_restriction = 60;

    /**
     * the protocol version the client has attempted to negotiate is recognized but not supported.
     * (for example, old protocol versions might be avoided for security reasons.) this message is
     * always fatal.
     */
    public static final short protocol_version = 70;

    /**
     * returned instead of handshake_failure when a negotiation has failed specifically because the
     * server requires ciphers more secure than those supported by the client. this message is
     * always fatal.
     */
    public static final short insufficient_security = 71;

    /**
     * an internal error unrelated to the peer or the correctness of the protocol (such as a memory
     * allocation failure) makes it impossible to continue. this message is always fatal.
     */
    public static final short internal_error = 80;

    /**
     * this handshake is being canceled for some reason unrelated to a protocol failure. if the user
     * cancels an operation after the handshake is complete, just closing the connection by sending
     * a close_notify is more appropriate. this alert should be followed by a close_notify. this
     * message is generally a warning.
     */
    public static final short user_canceled = 90;

    /**
     * sent by the client in response to a hello request or by the server in response to a client
     * hello after initial handshaking. either of these would normally lead to renegotiation; when
     * that is not appropriate, the recipient should respond with this alert. at that point, the
     * original requester can decide whether to proceed with the connection. one case where this
     * would be appropriate is where a server has spawned a process to satisfy a request; the
     * process might receive security parameters (key length, authentication, etc.) at startup, and
     * it might be difficult to communicate changes to these parameters after that point. this
     * message is always a warning.
     */
    public static final short no_renegotiation = 100;

    /**
     * sent by clients that receive an extended server hello containing an extension that they did
     * not put in the corresponding client hello. this message is always fatal.
     */
    public static final short unsupported_extension = 110;

    /*
     * rfc 3546
     */

    /**
     * this alert is sent by servers who are unable to retrieve a certificate chain from the url
     * supplied by the client (see section 3.3). this message may be fatal - for example if client
     * authentication is required by the server for the handshake to continue and the server is
     * unable to retrieve the certificate chain, it may send a fatal alert.
     */
    public static final short certificate_unobtainable = 111;

    /**
     * this alert is sent by servers that receive a server_name extension request, but do not
     * recognize the server name. this message may be fatal.
     */
    public static final short unrecognized_name = 112;

    /**
     * this alert is sent by clients that receive an invalid certificate status response (see
     * section 3.6). this message is always fatal.
     */
    public static final short bad_certificate_status_response = 113;

    /**
     * this alert is sent by servers when a certificate hash does not match a client provided
     * certificate_hash. this message is always fatal.
     */
    public static final short bad_certificate_hash_value = 114;

    /*
     * rfc 4279
     */

    /**
     * if the server does not recognize the psk identity, it may respond with an
     * "unknown_psk_identity" alert message.
     */
    public static final short unknown_psk_identity = 115;
}
