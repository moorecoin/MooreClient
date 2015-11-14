package org.ripple.bouncycastle.jce;

import org.ripple.bouncycastle.x509.x509storeparameters;

import java.security.cert.certstoreparameters;
import java.security.cert.ldapcertstoreparameters;

/**
 * an expanded set of parameters for an ldapcertstore
 */
public class x509ldapcertstoreparameters
    implements x509storeparameters, certstoreparameters
{

    private string ldapurl;

    private string basedn;

    // ldap attributes, where data is stored

    private string usercertificateattribute;

    private string cacertificateattribute;

    private string crosscertificateattribute;

    private string certificaterevocationlistattribute;

    private string deltarevocationlistattribute;

    private string authorityrevocationlistattribute;

    private string attributecertificateattributeattribute;

    private string aacertificateattribute;

    private string attributedescriptorcertificateattribute;

    private string attributecertificaterevocationlistattribute;

    private string attributeauthorityrevocationlistattribute;

    // ldap attributes with which data can be found

    private string ldapusercertificateattributename;

    private string ldapcacertificateattributename;

    private string ldapcrosscertificateattributename;

    private string ldapcertificaterevocationlistattributename;

    private string ldapdeltarevocationlistattributename;

    private string ldapauthorityrevocationlistattributename;

    private string ldapattributecertificateattributeattributename;

    private string ldapaacertificateattributename;

    private string ldapattributedescriptorcertificateattributename;

    private string ldapattributecertificaterevocationlistattributename;

    private string ldapattributeauthorityrevocationlistattributename;

    // certificates and crls subject or issuer dn attributes, which must be
    // matched against ldap attribute names

    private string usercertificatesubjectattributename;

    private string cacertificatesubjectattributename;

    private string crosscertificatesubjectattributename;

    private string certificaterevocationlistissuerattributename;

    private string deltarevocationlistissuerattributename;

    private string authorityrevocationlistissuerattributename;

    private string attributecertificateattributesubjectattributename;

    private string aacertificatesubjectattributename;

    private string attributedescriptorcertificatesubjectattributename;

    private string attributecertificaterevocationlistissuerattributename;

    private string attributeauthorityrevocationlistissuerattributename;

    private string searchforserialnumberin;

    public static class builder
    {
        private string ldapurl;

        private string basedn;

        // ldap attributes, where data is stored

        private string usercertificateattribute;

        private string cacertificateattribute;

        private string crosscertificateattribute;

        private string certificaterevocationlistattribute;

        private string deltarevocationlistattribute;

        private string authorityrevocationlistattribute;

        private string attributecertificateattributeattribute;

        private string aacertificateattribute;

        private string attributedescriptorcertificateattribute;

        private string attributecertificaterevocationlistattribute;

        private string attributeauthorityrevocationlistattribute;

        // ldap attributes with which data can be found

        private string ldapusercertificateattributename;

        private string ldapcacertificateattributename;

        private string ldapcrosscertificateattributename;

        private string ldapcertificaterevocationlistattributename;

        private string ldapdeltarevocationlistattributename;

        private string ldapauthorityrevocationlistattributename;

        private string ldapattributecertificateattributeattributename;

        private string ldapaacertificateattributename;

        private string ldapattributedescriptorcertificateattributename;

        private string ldapattributecertificaterevocationlistattributename;

        private string ldapattributeauthorityrevocationlistattributename;

        // certificates and crls subject or issuer dn attributes, which must be
        // matched against ldap attribute names

        private string usercertificatesubjectattributename;

        private string cacertificatesubjectattributename;

        private string crosscertificatesubjectattributename;

        private string certificaterevocationlistissuerattributename;

        private string deltarevocationlistissuerattributename;

        private string authorityrevocationlistissuerattributename;

        private string attributecertificateattributesubjectattributename;

        private string aacertificatesubjectattributename;

        private string attributedescriptorcertificatesubjectattributename;

        private string attributecertificaterevocationlistissuerattributename;

        private string attributeauthorityrevocationlistissuerattributename;

        private string searchforserialnumberin;

        public builder()
        {
            this("ldap://localhost:389", "");
        }

        public builder(string ldapurl, string basedn)
        {
            this.ldapurl = ldapurl;
            if (basedn == null)
            {
                this.basedn = "";
            }
            else
            {
                this.basedn = basedn;
            }

            this.usercertificateattribute = "usercertificate";
            this.cacertificateattribute = "cacertificate";
            this.crosscertificateattribute = "crosscertificatepair";
            this.certificaterevocationlistattribute = "certificaterevocationlist";
            this.deltarevocationlistattribute = "deltarevocationlist";
            this.authorityrevocationlistattribute = "authorityrevocationlist";
            this.attributecertificateattributeattribute = "attributecertificateattribute";
            this.aacertificateattribute = "aacertificate";
            this.attributedescriptorcertificateattribute = "attributedescriptorcertificate";
            this.attributecertificaterevocationlistattribute = "attributecertificaterevocationlist";
            this.attributeauthorityrevocationlistattribute = "attributeauthorityrevocationlist";
            this.ldapusercertificateattributename = "cn";
            this.ldapcacertificateattributename = "cn ou o";
            this.ldapcrosscertificateattributename = "cn ou o";
            this.ldapcertificaterevocationlistattributename = "cn ou o";
            this.ldapdeltarevocationlistattributename = "cn ou o";
            this.ldapauthorityrevocationlistattributename = "cn ou o";
            this.ldapattributecertificateattributeattributename = "cn";
            this.ldapaacertificateattributename = "cn o ou";
            this.ldapattributedescriptorcertificateattributename = "cn o ou";
            this.ldapattributecertificaterevocationlistattributename = "cn o ou";
            this.ldapattributeauthorityrevocationlistattributename = "cn o ou";
            this.usercertificatesubjectattributename = "cn";
            this.cacertificatesubjectattributename = "o ou";
            this.crosscertificatesubjectattributename = "o ou";
            this.certificaterevocationlistissuerattributename = "o ou";
            this.deltarevocationlistissuerattributename = "o ou";
            this.authorityrevocationlistissuerattributename = "o ou";
            this.attributecertificateattributesubjectattributename = "cn";
            this.aacertificatesubjectattributename = "o ou";
            this.attributedescriptorcertificatesubjectattributename = "o ou";
            this.attributecertificaterevocationlistissuerattributename = "o ou";
            this.attributeauthorityrevocationlistissuerattributename = "o ou";
            this.searchforserialnumberin = "uid serialnumber cn";
        }

        /**
         * @param usercertificateattribute       attribute name(s) in the ldap directory where end certificates
         *                                       are stored. separated by space. defaults to "usercertificate"
         *                                       if <code>null</code>.
         * @throws illegalargumentexception if a necessary parameter is <code>null</code>.
         * @return the builder
         */
        public builder setusercertificateattribute(string usercertificateattribute)
        {
            this.usercertificateattribute = usercertificateattribute;

            return this;
        }

        /**
         * @param cacertificateattribute         attribute name(s) in the ldap directory where ca certificates
         *                                       are stored. separated by space. defaults to "cacertificate" if
         *                                       <code>null</code>.
         * @throws illegalargumentexception if a necessary parameter is <code>null</code>.
         * @return the builder
         */
        public builder setcacertificateattribute(string cacertificateattribute)
        {
            this.cacertificateattribute = cacertificateattribute;

            return this;
        }

        /**
         * @param crosscertificateattribute      attribute name(s), where the cross certificates are stored.
         *                                       separated by space. defaults to "crosscertificatepair" if
         *                                       <code>null</code>
         * @throws illegalargumentexception if a necessary parameter is <code>null</code>.
         * @return the builder
         */
        public builder setcrosscertificateattribute(string crosscertificateattribute)
        {
            this.crosscertificateattribute = crosscertificateattribute;

            return this;
        }

        /**
         * @param certificaterevocationlistattribute
         *                                       attribute name(s) in the ldap directory where crls are stored.
         *                                       separated by space. defaults to "certificaterevocationlist" if
         *                                       <code>null</code>.
         * @throws illegalargumentexception if a necessary parameter is <code>null</code>.
         * @return the builder
         */
        public builder setcertificaterevocationlistattribute(string certificaterevocationlistattribute)
        {
            this.certificaterevocationlistattribute = certificaterevocationlistattribute;

            return this;
        }

        /**
         * @param deltarevocationlistattribute   attribute name(s) in the ldap directory where delta rls are
         *                                       stored. separated by space. defaults to "deltarevocationlist"
         *                                       if <code>null</code>.
         * @throws illegalargumentexception if a necessary parameter is <code>null</code>.
         * @return the builder
         */
        public builder setdeltarevocationlistattribute(string deltarevocationlistattribute)
        {
            this.deltarevocationlistattribute = deltarevocationlistattribute;

            return this;
        }

        /**
         * @param authorityrevocationlistattribute
         *                                       attribute name(s) in the ldap directory where crls for
         *                                       authorities are stored. separated by space. defaults to
         *                                       "authorityrevocationlist" if <code>null</code>.
         * @throws illegalargumentexception if a necessary parameter is <code>null</code>.
         * @return the builder
         */
        public builder setauthorityrevocationlistattribute(string authorityrevocationlistattribute)
        {
            this.authorityrevocationlistattribute = authorityrevocationlistattribute;

            return this;
        }

        /**
         * @param attributecertificateattributeattribute
         *                                       attribute name(s) in the ldap directory where end attribute
         *                                       certificates are stored. separated by space. defaults to
         *                                       "attributecertificateattribute" if <code>null</code>.
         * @throws illegalargumentexception if a necessary parameter is <code>null</code>.
         * @return the builder
         */
        public builder setattributecertificateattributeattribute(string attributecertificateattributeattribute)
        {
            this.attributecertificateattributeattribute = attributecertificateattributeattribute;

            return this;
        }

        /**
         * @param aacertificateattribute         attribute name(s) in the ldap directory where attribute
         *                                       certificates for attribute authorities are stored. separated
         *                                       by space. defaults to "aacertificate" if <code>null</code>.
         * @throws illegalargumentexception if a necessary parameter is <code>null</code>.
         * @return the builder
         */
        public builder setaacertificateattribute(string aacertificateattribute)
        {
            this.aacertificateattribute = aacertificateattribute;

            return this;
        }

        /**
         * @param attributedescriptorcertificateattribute
         *                                       attribute name(s) in the ldap directory where self signed
         *                                       attribute certificates for attribute authorities are stored.
         *                                       separated by space. defaults to
         *                                       "attributedescriptorcertificate" if <code>null</code>.
         * @throws illegalargumentexception if a necessary parameter is <code>null</code>.
         * @return the builder
         */
        public builder setattributedescriptorcertificateattribute(string attributedescriptorcertificateattribute)
        {
            this.attributedescriptorcertificateattribute = attributedescriptorcertificateattribute;

            return this;
        }

        /**
         * @param attributecertificaterevocationlistattribute
         *                                       attribute name(s) in the ldap directory where crls for
         *                                       attribute certificates are stored. separated by space.
         *                                       defaults to "attributecertificaterevocationlist" if
         *                                       <code>null</code>.
         * @throws illegalargumentexception if a necessary parameter is <code>null</code>.
         * @return the builder
         */
        public builder setattributecertificaterevocationlistattribute(string attributecertificaterevocationlistattribute)
        {
            this.attributecertificaterevocationlistattribute = attributecertificaterevocationlistattribute;

            return this;
        }

        /**
         * @param attributeauthorityrevocationlistattribute
         *                                       attribute name(s) in the ldap directory where rls for
         *                                       attribute authority attribute certificates are stored.
         *                                       separated by space. defaults to
         *                                       "attributeauthorityrevocationlist" if <code>null</code>.
         * @throws illegalargumentexception if a necessary parameter is <code>null</code>.
         * @return the builder
         */
        public builder setattributeauthorityrevocationlistattribute(string attributeauthorityrevocationlistattribute)
        {
            this.attributeauthorityrevocationlistattribute = attributeauthorityrevocationlistattribute;

            return this;
        }

        /**
         * @param ldapusercertificateattributename
         *                                       the attribute name(s) in the ldap directory where to search
         *                                       for the attribute value of the specified
         *                                       <code>usercertificatesubjectattributename</code>. e.g. if
         *                                       "cn" is used to put information about the subject for end
         *                                       certificates, then specify "cn".
         * @throws illegalargumentexception if a necessary parameter is <code>null</code>.
         * @return the builder
         */
        public builder setldapusercertificateattributename(string ldapusercertificateattributename)
        {
            this.ldapusercertificateattributename = ldapusercertificateattributename;

            return this;
        }

        /**
         * @param ldapcacertificateattributename the attribute name(s) in the ldap directory where to search
         *                                       for the attribute value of the specified
         *                                       <code>cacertificatesubjectattributename</code>. e.g. if
         *                                       "ou" is used to put information about the subject for ca
         *                                       certificates, then specify "ou".
         * @throws illegalargumentexception if a necessary parameter is <code>null</code>.
         * @return the builder
         */
        public builder setldapcacertificateattributename(string ldapcacertificateattributename)
        {
            this.ldapcacertificateattributename = ldapcacertificateattributename;

            return this;
        }

        /**
         * @param ldapcrosscertificateattributename
         *                                       the attribute name(s) in the ldap directory where to search for
         *                                       the attribute value of the specified
         *                                       <code>crosscertificatesubjectattributename</code>. e.g. if
         *                                       "o" is used to put information about the subject for cross
         *                                       certificates, then specify "o".
         * @throws illegalargumentexception if a necessary parameter is <code>null</code>.
         * @return the builder
         */
        public builder setldapcrosscertificateattributename(string ldapcrosscertificateattributename)
        {
            this.ldapcrosscertificateattributename = ldapcrosscertificateattributename;

            return this;
        }

        /**
         * @param ldapcertificaterevocationlistattributename
         *                                       the attribute name(s) in the ldap directory where to search for
         *                                       the attribute value of the specified
         *                                       <code>certificaterevocationlistissuerattributename</code>.
         *                                       e.g. if "ou" is used to put information about the issuer of
         *                                       crls, specify "ou".
         * @throws illegalargumentexception if a necessary parameter is <code>null</code>.
         * @return the builder
         */
        public builder setldapcertificaterevocationlistattributename(string ldapcertificaterevocationlistattributename)
        {
            this.ldapcertificaterevocationlistattributename = ldapcertificaterevocationlistattributename;

            return this;
        }

        /**
         * @param ldapdeltarevocationlistattributename
         *                                       the attribute name(s) in the ldap directory where to search for
         *                                       the attribute value of the specified
         *                                       <code>deltarevocationlistissuerattributename</code>. e.g.
         *                                       if "ou" is used to put information about the issuer of crls,
         *                                       specify "ou".
         * @throws illegalargumentexception if a necessary parameter is <code>null</code>.
         * @return the builder
         */
        public builder setldapdeltarevocationlistattributename(string ldapdeltarevocationlistattributename)
        {
            this.ldapdeltarevocationlistattributename = ldapdeltarevocationlistattributename;

            return this;
        }

        /**
         * @param ldapauthorityrevocationlistattributename
         *                                       the attribute name(s) in the ldap directory where to search for
         *                                       the attribute value of the specified
         *                                       <code>authorityrevocationlistissuerattributename</code>.
         *                                       e.g. if "ou" is used to put information about the issuer of
         *                                       crls, specify "ou".
         * @throws illegalargumentexception if a necessary parameter is <code>null</code>.
         * @return the builder
         */
        public builder setldapauthorityrevocationlistattributename(string ldapauthorityrevocationlistattributename)
        {
            this.ldapauthorityrevocationlistattributename = ldapauthorityrevocationlistattributename;

            return this;
        }

        /**
         * @param ldapattributecertificateattributeattributename
         *                                       the attribute name(s) in the ldap directory where to search for
         *                                       the attribute value of the specified
         *                                       <code>attributecertificateattributesubjectattributename</code>.
         *                                       e.g. if "cn" is used to put information about the subject of
         *                                       end attribute certificates, specify "cn".
         * @throws illegalargumentexception if a necessary parameter is <code>null</code>.
         * @return the builder
         */
        public builder setldapattributecertificateattributeattributename(string ldapattributecertificateattributeattributename)
        {
            this.ldapattributecertificateattributeattributename = ldapattributecertificateattributeattributename;

            return this;
        }

        /**
         * @param ldapaacertificateattributename the attribute name(s) in the ldap directory where to search for
         *                                       the attribute value of the specified
         *                                       <code>aacertificatesubjectattributename</code>. e.g. if
         *                                       "ou" is used to put information about the subject of attribute
         *                                       authority attribute certificates, specify "ou".
         * @throws illegalargumentexception if a necessary parameter is <code>null</code>.
         * @return the builder
         */
        public builder setldapaacertificateattributename(string ldapaacertificateattributename)
        {
            this.ldapaacertificateattributename = ldapaacertificateattributename;

            return this;
        }

        /**
         * @param ldapattributedescriptorcertificateattributename
         *                                       the attribute name(s) in the ldap directory where to search for
         *                                       the attribute value of the specified
         *                                       <code>attributedescriptorcertificatesubjectattributename</code>.
         *                                       e.g. if "o" is used to put information about the subject of
         *                                       self signed attribute authority attribute certificates,
         *                                       specify "o".
         * @throws illegalargumentexception if a necessary parameter is <code>null</code>.
         * @return the builder
         */
        public builder setldapattributedescriptorcertificateattributename(string ldapattributedescriptorcertificateattributename)
        {
            this.ldapattributedescriptorcertificateattributename = ldapattributedescriptorcertificateattributename;

            return this;
        }

        /**
         * @param ldapattributecertificaterevocationlistattributename
         *                                       the attribute name(s) in the ldap directory where to search for
         *                                       the attribute value of the specified
         *                                       <code>attributecertificaterevocationlistissuerattributename</code>.
         *                                       e.g. if "ou" is used to put information about the issuer of
         *                                       crls, specify "ou".
         * @throws illegalargumentexception if a necessary parameter is <code>null</code>.
         * @return the builder
         */
        public builder setldapattributecertificaterevocationlistattributename(string ldapattributecertificaterevocationlistattributename)
        {
            this.ldapattributecertificaterevocationlistattributename = ldapattributecertificaterevocationlistattributename;

            return this;
        }

        /**
         * @param ldapattributeauthorityrevocationlistattributename
         *                                       the attribute name(s) in the ldap directory where to search for
         *                                       the attribute value of the specified
         *                                       <code>attributeauthorityrevocationlistissuerattributename</code>.
         *                                       e.g. if "ou" is used to put information about the issuer of
         *                                       crls, specify "ou".
         * @throws illegalargumentexception if a necessary parameter is <code>null</code>.
         * @return the builder
         */
        public builder setldapattributeauthorityrevocationlistattributename(string ldapattributeauthorityrevocationlistattributename)
        {
            this.ldapattributeauthorityrevocationlistattributename = ldapattributeauthorityrevocationlistattributename;

            return this;
        }

        /**
         * @param usercertificatesubjectattributename
         *                                       attribute(s) in the subject of the certificate which is used
         *                                       to be searched in the
         *                                       <code>ldapusercertificateattributename</code>. e.g. the
         *                                       "cn" attribute of the dn could be used.
         * @throws illegalargumentexception if a necessary parameter is <code>null</code>.
         * @return the builder
         */
        public builder setusercertificatesubjectattributename(string usercertificatesubjectattributename)
        {
            this.usercertificatesubjectattributename = usercertificatesubjectattributename;

            return this;
        }

        /**
         * @param cacertificatesubjectattributename
         *                                       attribute(s) in the subject of the certificate which is used
         *                                       to be searched in the
         *                                       <code>ldapcacertificateattributename</code>. e.g. the "ou"
         *                                       attribute of the dn could be used.
         * @throws illegalargumentexception if a necessary parameter is <code>null</code>.
         * @return the builder
         */
        public builder setcacertificatesubjectattributename(string cacertificatesubjectattributename)
        {
            this.cacertificatesubjectattributename = cacertificatesubjectattributename;

            return this;
        }

        /**
         * @param crosscertificatesubjectattributename
         *                                       attribute(s) in the subject of the cross certificate which is
         *                                       used to be searched in the
         *                                       <code>ldapcrosscertificateattributename</code>. e.g. the
         *                                       "o" attribute of the dn may be appropriate.
         * @throws illegalargumentexception if a necessary parameter is <code>null</code>.
         * @return the builder
         */
        public builder setcrosscertificatesubjectattributename(string crosscertificatesubjectattributename)
        {
            this.crosscertificatesubjectattributename = crosscertificatesubjectattributename;

            return this;
        }

        /**
         * @param certificaterevocationlistissuerattributename
         *                                       attribute(s) in the issuer of the crl which is used to be
         *                                       searched in the
         *                                       <code>ldapcertificaterevocationlistattributename</code>.
         *                                       e.g. the "o" or "ou" attribute may be used.
         * @throws illegalargumentexception if a necessary parameter is <code>null</code>.
         * @return the builder
         */
        public builder setcertificaterevocationlistissuerattributename(string certificaterevocationlistissuerattributename)
        {
            this.certificaterevocationlistissuerattributename = certificaterevocationlistissuerattributename;

            return this;
        }

        /**
         * @param deltarevocationlistissuerattributename
         *                                       attribute(s) in the issuer of the crl which is used to be
         *                                       searched in the
         *                                       <code>ldapdeltarevocationlistattributename</code>. e.g. the
         *                                       "o" or "ou" attribute may be used.
         * @throws illegalargumentexception if a necessary parameter is <code>null</code>.
         * @return the builder
         */
        public builder setdeltarevocationlistissuerattributename(string deltarevocationlistissuerattributename)
        {
            this.deltarevocationlistissuerattributename = deltarevocationlistissuerattributename;

            return this;
        }

        /**
         * @param authorityrevocationlistissuerattributename
         *                                       attribute(s) in the issuer of the crl which is used to be
         *                                       searched in the
         *                                       <code>ldapauthorityrevocationlistattributename</code>. e.g.
         *                                       the "o" or "ou" attribute may be used.
         * @throws illegalargumentexception if a necessary parameter is <code>null</code>.
         * @return the builder
         */
        public builder setauthorityrevocationlistissuerattributename(string authorityrevocationlistissuerattributename)
        {
            this.authorityrevocationlistissuerattributename = authorityrevocationlistissuerattributename;

            return this;
        }

        /**
         * @param attributecertificateattributesubjectattributename
         *                                       attribute(s) in the subject of the attribute certificate which
         *                                       is used to be searched in the
         *                                       <code>ldapattributecertificateattributeattributename</code>.
         *                                       e.g. the "cn" attribute of the dn could be used.
         * @throws illegalargumentexception if a necessary parameter is <code>null</code>.
         * @return the builder
         */
        public builder setattributecertificateattributesubjectattributename(string attributecertificateattributesubjectattributename)
        {
            this.attributecertificateattributesubjectattributename = attributecertificateattributesubjectattributename;

            return this;
        }

        /**
         * @param aacertificatesubjectattributename
         *                                       attribute(s) in the subject of the attribute certificate which
         *                                       is used to be searched in the
         *                                       <code>ldapaacertificateattributename</code>. e.g. the "ou"
         *                                       attribute of the dn could be used.
         * @throws illegalargumentexception if a necessary parameter is <code>null</code>.
         * @return the builder
         */
        public builder setaacertificatesubjectattributename(string aacertificatesubjectattributename)
        {
            this.aacertificatesubjectattributename = aacertificatesubjectattributename;

            return this;
        }

        /**
         * @param attributedescriptorcertificatesubjectattributename
         *                                       attribute(s) in the subject of the attribute certificate which
         *                                       is used to be searched in the
         *                                       <code>ldapattributedescriptorcertificateattributename</code>.
         *                                       e.g. the "o" attribute of the dn could be used.
         * @throws illegalargumentexception if a necessary parameter is <code>null</code>.
         * @return the builder
         */
        public builder setattributedescriptorcertificatesubjectattributename(string attributedescriptorcertificatesubjectattributename)
        {
            this.attributedescriptorcertificatesubjectattributename = attributedescriptorcertificatesubjectattributename;

            return this;
        }

        /**
         * @param attributecertificaterevocationlistissuerattributename
         *                                       attribute(s) in the issuer of the crl which is used to be
         *                                       searched in the
         *                                       <code>ldapattributecertificaterevocationlistattributename</code>.
         *                                       e.g. the "o" or "ou" attribute may be used
         *                                       certificate is searched in this ldap attribute.
         * @throws illegalargumentexception if a necessary parameter is <code>null</code>.
         * @return the builder
         */
        public builder setattributecertificaterevocationlistissuerattributename(string attributecertificaterevocationlistissuerattributename)
        {
            this.attributecertificaterevocationlistissuerattributename = attributecertificaterevocationlistissuerattributename;

            return this;
        }

        /**
         * @param attributeauthorityrevocationlistissuerattributename
         *                                       anttribute(s) in the issuer of the crl which is used to be
         *                                       searched in the
         *                                       <code>ldapattributeauthorityrevocationlistattributename</code>.
         *                                       e.g. the "o" or "ou" attribute may be used.
         * @throws illegalargumentexception if a necessary parameter is <code>null</code>.
         * @return the builder
         */
        public builder setattributeauthorityrevocationlistissuerattributename(string attributeauthorityrevocationlistissuerattributename)
        {
            this.attributeauthorityrevocationlistissuerattributename = attributeauthorityrevocationlistissuerattributename;

            return this;
        }

        /**
         *
         * @param searchforserialnumberin        if not <code>null</code> the serial number of the
         *                                       certificate is searched in this ldap attribute.
         * @throws illegalargumentexception if a necessary parameter is <code>null</code>.
         * @return the builder
         */
        public builder setsearchforserialnumberin(string searchforserialnumberin)
        {
            this.searchforserialnumberin = searchforserialnumberin;

            return this;
        }

        public x509ldapcertstoreparameters build()
        {
             if (ldapusercertificateattributename == null   // migrate to setters
                || ldapcacertificateattributename == null
                || ldapcrosscertificateattributename == null
                || ldapcertificaterevocationlistattributename == null
                || ldapdeltarevocationlistattributename == null
                || ldapauthorityrevocationlistattributename == null
                || ldapattributecertificateattributeattributename == null
                || ldapaacertificateattributename == null
                || ldapattributedescriptorcertificateattributename == null
                || ldapattributecertificaterevocationlistattributename == null
                || ldapattributeauthorityrevocationlistattributename == null
                || usercertificatesubjectattributename == null
                || cacertificatesubjectattributename == null
                || crosscertificatesubjectattributename == null
                || certificaterevocationlistissuerattributename == null
                || deltarevocationlistissuerattributename == null
                || authorityrevocationlistissuerattributename == null
                || attributecertificateattributesubjectattributename == null
                || aacertificatesubjectattributename == null
                || attributedescriptorcertificatesubjectattributename == null
                || attributecertificaterevocationlistissuerattributename == null
                || attributeauthorityrevocationlistissuerattributename == null)
            {
                throw new illegalargumentexception(
                    "necessary parameters not specified.");
            }
            return new x509ldapcertstoreparameters(this);
        }
    }


    private x509ldapcertstoreparameters(builder builder)
    {
        this.ldapurl = builder.ldapurl;
        this.basedn = builder.basedn;

        this.usercertificateattribute = builder.usercertificateattribute;
        this.cacertificateattribute = builder.cacertificateattribute;
        this.crosscertificateattribute = builder.crosscertificateattribute;
        this.certificaterevocationlistattribute = builder.certificaterevocationlistattribute;
        this.deltarevocationlistattribute = builder.deltarevocationlistattribute;
        this.authorityrevocationlistattribute = builder.authorityrevocationlistattribute;
        this.attributecertificateattributeattribute = builder.attributecertificateattributeattribute;
        this.aacertificateattribute = builder.aacertificateattribute;
        this.attributedescriptorcertificateattribute = builder.attributedescriptorcertificateattribute;
        this.attributecertificaterevocationlistattribute = builder.attributecertificaterevocationlistattribute;
        this.attributeauthorityrevocationlistattribute = builder.attributeauthorityrevocationlistattribute;
        this.ldapusercertificateattributename = builder.ldapusercertificateattributename;
        this.ldapcacertificateattributename = builder.ldapcacertificateattributename;
        this.ldapcrosscertificateattributename = builder.ldapcrosscertificateattributename;
        this.ldapcertificaterevocationlistattributename = builder.ldapcertificaterevocationlistattributename;
        this.ldapdeltarevocationlistattributename = builder.ldapdeltarevocationlistattributename;
        this.ldapauthorityrevocationlistattributename = builder.ldapauthorityrevocationlistattributename;
        this.ldapattributecertificateattributeattributename = builder.ldapattributecertificateattributeattributename;
        this.ldapaacertificateattributename = builder.ldapaacertificateattributename;
        this.ldapattributedescriptorcertificateattributename = builder.ldapattributedescriptorcertificateattributename;
        this.ldapattributecertificaterevocationlistattributename = builder.ldapattributecertificaterevocationlistattributename;
        this.ldapattributeauthorityrevocationlistattributename = builder.ldapattributeauthorityrevocationlistattributename;
        this.usercertificatesubjectattributename = builder.usercertificatesubjectattributename;
        this.cacertificatesubjectattributename = builder.cacertificatesubjectattributename;
        this.crosscertificatesubjectattributename = builder.crosscertificatesubjectattributename;
        this.certificaterevocationlistissuerattributename = builder.certificaterevocationlistissuerattributename;
        this.deltarevocationlistissuerattributename = builder.deltarevocationlistissuerattributename;
        this.authorityrevocationlistissuerattributename = builder.authorityrevocationlistissuerattributename;
        this.attributecertificateattributesubjectattributename = builder.attributecertificateattributesubjectattributename;
        this.aacertificatesubjectattributename = builder.aacertificatesubjectattributename;
        this.attributedescriptorcertificatesubjectattributename = builder.attributedescriptorcertificatesubjectattributename;
        this.attributecertificaterevocationlistissuerattributename = builder.attributecertificaterevocationlistissuerattributename;
        this.attributeauthorityrevocationlistissuerattributename = builder.attributeauthorityrevocationlistissuerattributename;
        this.searchforserialnumberin = builder.searchforserialnumberin;
    }

    /**
     * returns a clone of this object.
     */
    public object clone()
    {
        return this;
    }

    public boolean equal(object o)
    {
        if (o == this)
        {
            return true;
        }

        if (!(o instanceof x509ldapcertstoreparameters))
        {
            return false;
        }

        x509ldapcertstoreparameters params = (x509ldapcertstoreparameters)o;
        return checkfield(ldapurl, params.ldapurl)
            && checkfield(basedn, params.basedn)
            && checkfield(usercertificateattribute, params.usercertificateattribute)
            && checkfield(cacertificateattribute, params.cacertificateattribute)
            && checkfield(crosscertificateattribute, params.crosscertificateattribute)
            && checkfield(certificaterevocationlistattribute, params.certificaterevocationlistattribute)
            && checkfield(deltarevocationlistattribute, params.deltarevocationlistattribute)
            && checkfield(authorityrevocationlistattribute, params.authorityrevocationlistattribute)
            && checkfield(attributecertificateattributeattribute, params.attributecertificateattributeattribute)
            && checkfield(aacertificateattribute, params.aacertificateattribute)
            && checkfield(attributedescriptorcertificateattribute, params.attributedescriptorcertificateattribute)
            && checkfield(attributecertificaterevocationlistattribute, params.attributecertificaterevocationlistattribute)
            && checkfield(attributeauthorityrevocationlistattribute, params.attributeauthorityrevocationlistattribute)
            && checkfield(ldapusercertificateattributename, params.ldapusercertificateattributename)
            && checkfield(ldapcacertificateattributename, params.ldapcacertificateattributename)
            && checkfield(ldapcrosscertificateattributename, params.ldapcrosscertificateattributename)
            && checkfield(ldapcertificaterevocationlistattributename, params.ldapcertificaterevocationlistattributename)
            && checkfield(ldapdeltarevocationlistattributename, params.ldapdeltarevocationlistattributename)
            && checkfield(ldapauthorityrevocationlistattributename, params.ldapauthorityrevocationlistattributename)
            && checkfield(ldapattributecertificateattributeattributename, params.ldapattributecertificateattributeattributename)
            && checkfield(ldapaacertificateattributename, params.ldapaacertificateattributename)
            && checkfield(ldapattributedescriptorcertificateattributename, params.ldapattributedescriptorcertificateattributename)
            && checkfield(ldapattributecertificaterevocationlistattributename, params.ldapattributecertificaterevocationlistattributename)
            && checkfield(ldapattributeauthorityrevocationlistattributename, params.ldapattributeauthorityrevocationlistattributename)
            && checkfield(usercertificatesubjectattributename, params.usercertificatesubjectattributename)
            && checkfield(cacertificatesubjectattributename, params.cacertificatesubjectattributename)
            && checkfield(crosscertificatesubjectattributename, params.crosscertificatesubjectattributename)
            && checkfield(certificaterevocationlistissuerattributename, params.certificaterevocationlistissuerattributename)
            && checkfield(deltarevocationlistissuerattributename, params.deltarevocationlistissuerattributename)
            && checkfield(authorityrevocationlistissuerattributename, params.authorityrevocationlistissuerattributename)
            && checkfield(attributecertificateattributesubjectattributename, params.attributecertificateattributesubjectattributename)
            && checkfield(aacertificatesubjectattributename, params.aacertificatesubjectattributename)
            && checkfield(attributedescriptorcertificatesubjectattributename, params.attributedescriptorcertificatesubjectattributename)
            && checkfield(attributecertificaterevocationlistissuerattributename, params.attributecertificaterevocationlistissuerattributename)
            && checkfield(attributeauthorityrevocationlistissuerattributename, params.attributeauthorityrevocationlistissuerattributename)
            && checkfield(searchforserialnumberin, params.searchforserialnumberin);
    }

    private boolean checkfield(object o1, object o2)
    {
        if (o1 == o2)
        {
            return true;
        }

        if (o1 == null)
        {
            return false;
        }

        return o1.equals(o2);
    }

    public int hashcode()
    {
        int hash = 0;

        hash = addhashcode(hash, usercertificateattribute);
        hash = addhashcode(hash, cacertificateattribute);
        hash = addhashcode(hash, crosscertificateattribute);
        hash = addhashcode(hash, certificaterevocationlistattribute);
        hash = addhashcode(hash, deltarevocationlistattribute);
        hash = addhashcode(hash, authorityrevocationlistattribute);
        hash = addhashcode(hash, attributecertificateattributeattribute);
        hash = addhashcode(hash, aacertificateattribute);
        hash = addhashcode(hash, attributedescriptorcertificateattribute);
        hash = addhashcode(hash, attributecertificaterevocationlistattribute);
        hash = addhashcode(hash, attributeauthorityrevocationlistattribute);
        hash = addhashcode(hash, ldapusercertificateattributename);
        hash = addhashcode(hash, ldapcacertificateattributename);
        hash = addhashcode(hash, ldapcrosscertificateattributename);
        hash = addhashcode(hash, ldapcertificaterevocationlistattributename);
        hash = addhashcode(hash, ldapdeltarevocationlistattributename);
        hash = addhashcode(hash, ldapauthorityrevocationlistattributename);
        hash = addhashcode(hash, ldapattributecertificateattributeattributename);
        hash = addhashcode(hash, ldapaacertificateattributename);
        hash = addhashcode(hash, ldapattributedescriptorcertificateattributename);
        hash = addhashcode(hash, ldapattributecertificaterevocationlistattributename);
        hash = addhashcode(hash, ldapattributeauthorityrevocationlistattributename);
        hash = addhashcode(hash, usercertificatesubjectattributename);
        hash = addhashcode(hash, cacertificatesubjectattributename);
        hash = addhashcode(hash, crosscertificatesubjectattributename);
        hash = addhashcode(hash, certificaterevocationlistissuerattributename);
        hash = addhashcode(hash, deltarevocationlistissuerattributename);
        hash = addhashcode(hash, authorityrevocationlistissuerattributename);
        hash = addhashcode(hash, attributecertificateattributesubjectattributename);
        hash = addhashcode(hash, aacertificatesubjectattributename);
        hash = addhashcode(hash, attributedescriptorcertificatesubjectattributename);
        hash = addhashcode(hash, attributecertificaterevocationlistissuerattributename);
        hash = addhashcode(hash, attributeauthorityrevocationlistissuerattributename);
        hash = addhashcode(hash, searchforserialnumberin);
        
        return hash;
    }

    private int addhashcode(int hashcode, object o)
    {
        return (hashcode * 29) + (o == null ? 0 : o.hashcode());
    }

    /**
     * @return returns the aacertificateattribute.
     */
    public string getaacertificateattribute()
    {
        return aacertificateattribute;
    }

    /**
     * @return returns the aacertificatesubjectattributename.
     */
    public string getaacertificatesubjectattributename()
    {
        return aacertificatesubjectattributename;
    }

    /**
     * @return returns the attributeauthorityrevocationlistattribute.
     */
    public string getattributeauthorityrevocationlistattribute()
    {
        return attributeauthorityrevocationlistattribute;
    }

    /**
     * @return returns the attributeauthorityrevocationlistissuerattributename.
     */
    public string getattributeauthorityrevocationlistissuerattributename()
    {
        return attributeauthorityrevocationlistissuerattributename;
    }

    /**
     * @return returns the attributecertificateattributeattribute.
     */
    public string getattributecertificateattributeattribute()
    {
        return attributecertificateattributeattribute;
    }

    /**
     * @return returns the attributecertificateattributesubjectattributename.
     */
    public string getattributecertificateattributesubjectattributename()
    {
        return attributecertificateattributesubjectattributename;
    }

    /**
     * @return returns the attributecertificaterevocationlistattribute.
     */
    public string getattributecertificaterevocationlistattribute()
    {
        return attributecertificaterevocationlistattribute;
    }

    /**
     * @return returns the
     *         attributecertificaterevocationlistissuerattributename.
     */
    public string getattributecertificaterevocationlistissuerattributename()
    {
        return attributecertificaterevocationlistissuerattributename;
    }

    /**
     * @return returns the attributedescriptorcertificateattribute.
     */
    public string getattributedescriptorcertificateattribute()
    {
        return attributedescriptorcertificateattribute;
    }

    /**
     * @return returns the attributedescriptorcertificatesubjectattributename.
     */
    public string getattributedescriptorcertificatesubjectattributename()
    {
        return attributedescriptorcertificatesubjectattributename;
    }

    /**
     * @return returns the authorityrevocationlistattribute.
     */
    public string getauthorityrevocationlistattribute()
    {
        return authorityrevocationlistattribute;
    }

    /**
     * @return returns the authorityrevocationlistissuerattributename.
     */
    public string getauthorityrevocationlistissuerattributename()
    {
        return authorityrevocationlistissuerattributename;
    }

    /**
     * @return returns the basedn.
     */
    public string getbasedn()
    {
        return basedn;
    }

    /**
     * @return returns the cacertificateattribute.
     */
    public string getcacertificateattribute()
    {
        return cacertificateattribute;
    }

    /**
     * @return returns the cacertificatesubjectattributename.
     */
    public string getcacertificatesubjectattributename()
    {
        return cacertificatesubjectattributename;
    }

    /**
     * @return returns the certificaterevocationlistattribute.
     */
    public string getcertificaterevocationlistattribute()
    {
        return certificaterevocationlistattribute;
    }

    /**
     * @return returns the certificaterevocationlistissuerattributename.
     */
    public string getcertificaterevocationlistissuerattributename()
    {
        return certificaterevocationlistissuerattributename;
    }

    /**
     * @return returns the crosscertificateattribute.
     */
    public string getcrosscertificateattribute()
    {
        return crosscertificateattribute;
    }

    /**
     * @return returns the crosscertificatesubjectattributename.
     */
    public string getcrosscertificatesubjectattributename()
    {
        return crosscertificatesubjectattributename;
    }

    /**
     * @return returns the deltarevocationlistattribute.
     */
    public string getdeltarevocationlistattribute()
    {
        return deltarevocationlistattribute;
    }

    /**
     * @return returns the deltarevocationlistissuerattributename.
     */
    public string getdeltarevocationlistissuerattributename()
    {
        return deltarevocationlistissuerattributename;
    }

    /**
     * @return returns the ldapaacertificateattributename.
     */
    public string getldapaacertificateattributename()
    {
        return ldapaacertificateattributename;
    }

    /**
     * @return returns the ldapattributeauthorityrevocationlistattributename.
     */
    public string getldapattributeauthorityrevocationlistattributename()
    {
        return ldapattributeauthorityrevocationlistattributename;
    }

    /**
     * @return returns the ldapattributecertificateattributeattributename.
     */
    public string getldapattributecertificateattributeattributename()
    {
        return ldapattributecertificateattributeattributename;
    }

    /**
     * @return returns the ldapattributecertificaterevocationlistattributename.
     */
    public string getldapattributecertificaterevocationlistattributename()
    {
        return ldapattributecertificaterevocationlistattributename;
    }

    /**
     * @return returns the ldapattributedescriptorcertificateattributename.
     */
    public string getldapattributedescriptorcertificateattributename()
    {
        return ldapattributedescriptorcertificateattributename;
    }

    /**
     * @return returns the ldapauthorityrevocationlistattributename.
     */
    public string getldapauthorityrevocationlistattributename()
    {
        return ldapauthorityrevocationlistattributename;
    }

    /**
     * @return returns the ldapcacertificateattributename.
     */
    public string getldapcacertificateattributename()
    {
        return ldapcacertificateattributename;
    }

    /**
     * @return returns the ldapcertificaterevocationlistattributename.
     */
    public string getldapcertificaterevocationlistattributename()
    {
        return ldapcertificaterevocationlistattributename;
    }

    /**
     * @return returns the ldapcrosscertificateattributename.
     */
    public string getldapcrosscertificateattributename()
    {
        return ldapcrosscertificateattributename;
    }

    /**
     * @return returns the ldapdeltarevocationlistattributename.
     */
    public string getldapdeltarevocationlistattributename()
    {
        return ldapdeltarevocationlistattributename;
    }

    /**
     * @return returns the ldapurl.
     */
    public string getldapurl()
    {
        return ldapurl;
    }

    /**
     * @return returns the ldapusercertificateattributename.
     */
    public string getldapusercertificateattributename()
    {
        return ldapusercertificateattributename;
    }

    /**
     * @return returns the searchforserialnumberin.
     */
    public string getsearchforserialnumberin()
    {
        return searchforserialnumberin;
    }

    /**
     * @return returns the usercertificateattribute.
     */
    public string getusercertificateattribute()
    {
        return usercertificateattribute;
    }

    /**
     * @return returns the usercertificatesubjectattributename.
     */
    public string getusercertificatesubjectattributename()
    {
        return usercertificatesubjectattributename;
    }

    public static x509ldapcertstoreparameters getinstance(ldapcertstoreparameters params)
    {
        string server = "ldap://" + params.getservername() + ":" + params.getport();
        x509ldapcertstoreparameters _params = new builder(server, "").build();
        return _params;
    }
}
