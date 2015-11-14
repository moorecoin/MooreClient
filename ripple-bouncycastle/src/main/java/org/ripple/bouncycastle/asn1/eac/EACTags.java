package org.ripple.bouncycastle.asn1.eac;

import org.ripple.bouncycastle.asn1.bertags;
import org.ripple.bouncycastle.asn1.derapplicationspecific;

public class eactags
{
    public static final int object_identifier = 0x06;
    public static final int country_code_national_data = 0x41;
    public static final int issuer_identification_number = 0x02; //0x42;
    public static final int card_service_data = 0x43;
    public static final int initial_access_data = 0x44;
    public static final int card_issuer_data = 0x45;
    public static final int pre_issuing_data = 0x46;
    public static final int card_capabilities = 0x47;
    public static final int status_information = 0x48;
    public static final int extended_header_list = 0x4d;
    public static final int application_identifier = 0x4f;
    public static final int application_label = 0x50;
    public static final int file_reference = 0x51;
    public static final int command_to_perform = 0x52;
    public static final int discretionary_data = 0x53;
    public static final int offset_data_object = 0x54;
    public static final int track1_application = 0x56;
    public static final int track2_application = 0x57;
    public static final int track3_application = 0x58;
    public static final int card_expiration_data = 0x59;
    public static final int primary_account_number = 0x5a;// pan
    public static final int name = 0x5b;
    public static final int tag_list = 0x5c;
    public static final int header_list = 0x5d;
    public static final int login_data = 0x5e;
    public static final int cardholder_name = 0x20; // 0x5f20;
    public static final int track1_card = 0x5f21;
    public static final int track2_card = 0x5f22;
    public static final int track3_card = 0x5f23;
    public static final int application_expiration_date = 0x24; // 0x5f24;
    public static final int application_effective_date = 0x25; // 0x5f25;
    public static final int card_effective_date = 0x5f26;
    public static final int interchange_control = 0x5f27;
    public static final int country_code = 0x5f28;
    public static final int interchange_profile = 0x29; // 0x5f29;
    public static final int currency_code = 0x5f2a;
    public static final int date_of_birth = 0x5f2b;
    public static final int cardholder_nationality = 0x5f2c;
    public static final int language_preferences = 0x5f2d;
    public static final int cardholder_biometric_data = 0x5f2e;
    public static final int pin_usage_policy = 0x5f2f;
    public static final int service_code = 0x5f30;
    public static final int transaction_counter = 0x5f32;
    public static final int transaction_date = 0x5f33;
    public static final int card_sequence_number = 0x5f34;
    public static final int sex = 0x5f35;
    public static final int currency_exponent = 0x5f36;
    public static final int static_internal_authentification_one_step = 0x37; // 0x5f37;
    public static final int signature = 0x5f37;
    public static final int static_internal_authentification_first_data = 0x5f38;
    public static final int static_internal_authentification_second_data = 0x5f39;
    public static final int dynamic_internal_authentification = 0x5f3a;
    public static final int dynamic_external_authentification = 0x5f3b;
    public static final int dynamic_mutual_authentification = 0x5f3c;
    public static final int cardholder_portrait_image = 0x5f40;
    public static final int element_list = 0x5f41;
    public static final int address = 0x5f42;
    public static final int cardholder_handwritten_signature = 0x5f43;
    public static final int application_image = 0x5f44;
    public static final int display_image = 0x5f45;
    public static final int timer = 0x5f46;
    public static final int message_reference = 0x5f47;
    public static final int cardholder_private_key = 0x5f48;
    public static final int cardholder_public_key = 0x5f49;
    public static final int certification_authority_public_key = 0x5f4a;
    public static final int deprecated = 0x5f4b;
    public static final int certificate_holder_authorization = 0x5f4c;// not yet defined in iso7816. the allocation is requested
    public static final int integrated_circuit_manufacturer_id = 0x5f4d;
    public static final int certificate_content = 0x5f4e;
    public static final int uniform_resource_locator = 0x5f50;
    public static final int answer_to_reset = 0x5f51;
    public static final int historical_bytes = 0x5f52;
    public static final int digital_signature = 0x5f3d;
    public static final int application_template = 0x61;
    public static final int fcp_template = 0x62;
    public static final int wrapper = 0x63;
    public static final int fmd_template = 0x64;
    public static final int cardholder_relative_data = 0x65;
    public static final int card_data = 0x66;
    public static final int authentification_data = 0x67;
    public static final int special_user_requirements = 0x68;
    public static final int login_template = 0x6a;
    public static final int qualified_name = 0x6b;
    public static final int cardholder_image_template = 0x6c;
    public static final int application_image_template = 0x6d;
    public static final int application_related_data = 0x6e;
    public static final int fci_template = 0x6f;
    public static final int discretionary_data_objects = 0x73;
    public static final int compatible_tag_allocation_authority = 0x78;
    public static final int coexistant_tag_allocation_authority = 0x79;
    public static final int security_support_template = 0x7a;
    public static final int security_environment_template = 0x7b;
    public static final int dynamic_authentification_template = 0x7c;
    public static final int secure_messaging_template = 0x7d;
    public static final int non_interindustry_data_object_nesting_template = 0x7e;
    public static final int display_control = 0x7f20;
    public static final int cardholder_certificate = 0x21; // 0x7f21;
    public static final int cv_certificate = 0x7f21;
    public static final int cardholer_requirements_included_features = 0x7f22;
    public static final int cardholer_requirements_excluded_features = 0x7f23;
    public static final int biometric_data_template = 0x7f2e;
    public static final int digital_signature_block = 0x7f3d;
    public static final int cardholder_private_key_template = 0x7f48;
    public static final int cardholder_public_key_template = 0x49; // 0x7f49;
    public static final int certificate_holder_authorization_template = 0x4c; // 0x7f4c;
    public static final int certificate_content_template = 0x4e; // 0x7f4e;
    public static final int certificate_body = 0x4e; // 0x7f4e;
    public static final int biometric_information_template = 0x7f60;
    public static final int biometric_information_group_template = 0x7f61;

    public static int gettag(int encodedtag)
    {
        /*
        int i;
        for (i = 24; i>=0; i-=8) {
            if (((0xff<<i) & tag) != 0)
                return (((0xff<<i) & tag) >> i);
        }
        return 0;
        */
        return decodetag(encodedtag);
    }

    public static int gettagno(int tag)
    {
        int i;
        for (i = 24; i >= 0; i -= 8)
        {
            if (((0xff << i) & tag) != 0)
            {
                return ((~(0xff << i)) & tag);
            }
        }
        return 0;
    }

    public static int encodetag(derapplicationspecific spec)
    {
        int retvalue = bertags.application;
        boolean constructed = spec.isconstructed();
        if (constructed)
        {
            retvalue |= bertags.constructed;
        }

        int tag = spec.getapplicationtag();

        if (tag > 31)
        {
            retvalue |= 0x1f;
            retvalue <<= 8;

            int currentbyte = tag & 0x7f;
            retvalue |= currentbyte;
            tag >>= 7;

            while (tag > 0)
            {
                retvalue |= 0x80;
                retvalue <<= 8;

                currentbyte = tag & 0x7f;
                tag >>= 7;
            }
        }
        else
        {
            retvalue |= tag;
        }

        return retvalue;
    }

    public static int decodetag(int tag)
    {
        int retvalue = 0;
        boolean multibytes = false;
        for (int i = 24; i >= 0; i -= 8)
        {
            int currentbyte = tag >> i & 0xff;
            if (currentbyte == 0)
            {
                continue;
            }

            if (multibytes)
            {
                retvalue <<= 7;
                retvalue |= currentbyte & 0x7f;
            }
            else if ((currentbyte & 0x1f) == 0x1f)
            {
                multibytes = true;
            }
            else
            {
                return currentbyte & 0x1f; // higher order bit are for der.constructed and type
            }
        }
        return retvalue;
    }
}
