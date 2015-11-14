package org.moorecoinlab.api;


public class apiexception extends runtimeexception{

    public static enum errorcode{
        internal_error,
        user_not_found,
        unknown_error,
        address_not_found,
        address_format_malformed,
        remote_error,
        malformed_request_data,
        unsupported_currency,
        not_loggedin,
        incorrect_password,
        nick_exists,
        not_received_currency,
        not_enough_balance,
        account_lock,
        is_gateway,
        activated_error,
        sendmail_error,
        emial_exists,
        masterkey_exists,
        masterkey_format_error,
        nick_invalid,
        too_many_requests,
        pay_password_set_failed,
        user_not_set_paypassword,
        paypassword_error,
        user_has_set_paypassword
    }

    public errorcode code;
    public string message;

    public apiexception(errorcode code, string message){
        super(message);
        this.code = code;
        this.message = message;
    }

    public apiexception(string message){
        super(message);
        this.message = message;
    }
}
