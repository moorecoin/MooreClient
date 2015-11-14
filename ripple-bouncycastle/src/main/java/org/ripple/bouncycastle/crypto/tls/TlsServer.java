package org.ripple.bouncycastle.crypto.tls;

import java.io.ioexception;
import java.util.hashtable;
import java.util.vector;

public interface tlsserver
    extends tlspeer
{

    void init(tlsservercontext context);

    void notifyclientversion(protocolversion clientversion)
        throws ioexception;

    void notifyofferedciphersuites(int[] offeredciphersuites)
        throws ioexception;

    void notifyofferedcompressionmethods(short[] offeredcompressionmethods)
        throws ioexception;

    void notifysecurerenegotiation(boolean securenegotiation)
        throws ioexception;

    // hashtable is (integer -> byte[])
    void processclientextensions(hashtable clientextensions)
        throws ioexception;

    protocolversion getserverversion()
        throws ioexception;

    int getselectedciphersuite()
        throws ioexception;

    short getselectedcompressionmethod()
        throws ioexception;

    // hashtable is (integer -> byte[])
    hashtable getserverextensions()
        throws ioexception;

    // vector is (supplementaldataentry)
    vector getserversupplementaldata()
        throws ioexception;

    tlscredentials getcredentials()
        throws ioexception;

    tlskeyexchange getkeyexchange()
        throws ioexception;

    certificaterequest getcertificaterequest();

    // vector is (supplementaldataentry)
    void processclientsupplementaldata(vector clientsupplementaldata)
        throws ioexception;

    /**
     * called by the protocol handler to report the client certificate, only if a certificate
     * {@link #getcertificaterequest()} returned non-null. note: this method is responsible for
     * certificate verification and validation.
     *
     * @param clientcertificate the effective client certificate (may be an empty chain).
     * @throws ioexception
     */
    void notifyclientcertificate(certificate clientcertificate)
        throws ioexception;

    tlscompression getcompression()
        throws ioexception;

    tlscipher getcipher()
        throws ioexception;

    /**
     * rfc 5077 3.3. newsessionticket handshake message.
     * <p/>
     * this method will be called (only) if a newsessionticket extension was sent by the server. see
     * <i>rfc 5077 4. recommended ticket construction</i> for recommended format and protection.
     *
     * @return the ticket.
     * @throws ioexception
     */
    newsessionticket getnewsessionticket()
        throws ioexception;

    void notifyhandshakecomplete()
        throws ioexception;
}
