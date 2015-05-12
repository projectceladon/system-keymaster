/*
 * Copyright (C) 2014 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <string.h>
#include <time.h>

#include "google_keymaster_test_utils.h"
#include "keymaster_enforcement.h"

namespace keymaster {

KeymasterEnforcement::KeymasterEnforcement() {
    last_auth_time = -1;
}

KeymasterEnforcement::~KeymasterEnforcement() {
}

keymaster_error_t KeymasterEnforcement::AuthorizeOperation(const keymaster_purpose_t purpose,
                                                           const km_id_t keyid,
                                                           const AuthorizationSet& auth_set,
                                                           const uid_t uid) {
    time_t current_time;
    keymaster_error_t return_error;

    /* Pairs of tags that are incompatible and should return an error. */
    bool tag_all_users_present = false;
    bool tag_user_id_present = false;

    bool tag_user_auth_id_present = false;
    bool tag_no_auth_required_present = false;

    bool tag_all_applications_present = false;
    bool tag_application_id_present = false;

    return_error = KM_ERROR_OK;
    current_time = get_current_time();

    int auth_timeout_index = auth_set.find(KM_TAG_AUTH_TIMEOUT);
    if (auth_timeout_index < 0) {
        /* TODO: Require Authentication. Method TBD. */
    }

    if ((return_error = valid_purpose(purpose, auth_set)) != KM_ERROR_OK)
        return return_error;

    for (unsigned int i = 0; i < auth_set.size(); i++) {
        keymaster_key_param_t param = auth_set[i];

        // KM_TAG_PADDING_OLD and KM_TAG_DIGEST_OLD aren't actually members of the enum, so we can't
        // switch on them.  There's nothing to validate for them, though, so just ignore them.
        if (param.tag == KM_TAG_PADDING_OLD || param.tag == KM_TAG_DIGEST_OLD)
            continue;

        switch (param.tag) {
        case KM_TAG_ACTIVE_DATETIME:
            return_error = Active(param, current_time);
            break;
        case KM_TAG_ORIGINATION_EXPIRE_DATETIME:
            return_error = OriginationNotExpired(param, current_time, purpose);
            break;
        case KM_TAG_USAGE_EXPIRE_DATETIME:
            return_error = UsageNotExpired(param, current_time, purpose);
            break;
        case KM_TAG_MIN_SECONDS_BETWEEN_OPS:
            return_error = MinTimeBetweenOpsPassed(param, keyid, current_time);
            break;
        case KM_TAG_MAX_USES_PER_BOOT:
            return_error = NotUsedSinceBoot(keyid);
            break;
        case KM_TAG_ALL_USERS:
            tag_all_users_present = true;
            return_error = KM_ERROR_OK;
            break;
        case KM_TAG_USER_ID:
            tag_user_id_present = true;
            return_error = UserAuthenticated(param, uid);
            break;
        case KM_TAG_USER_SECURE_ID:
            // TODO(swillden): Handle this.
            break;
        case KM_TAG_AUTH_TOKEN:
            // TODO(swillden): Handle this.
            break;
        case KM_TAG_NO_AUTH_REQUIRED:
            return_error = KM_ERROR_OK;
            tag_no_auth_required_present = true;
            break;
        case KM_TAG_USER_AUTH_TYPE:
            tag_user_auth_id_present = true;
            return_error = KM_ERROR_OK;
            break;
        case KM_TAG_AUTH_TIMEOUT:
            return_error = AuthenticationIsFresh(param, current_time);
            break;
        case KM_TAG_ALL_APPLICATIONS:
            tag_all_applications_present = true;
            break;
        case KM_TAG_APPLICATION_ID:
            tag_application_id_present = true;
            break;
        case KM_TAG_CALLER_NONCE:
            // TODO(swillden): Handle this tag.  For now it's ignored.
            break;

        /* Invalid tag is not used for access control. */
        case KM_TAG_INVALID:

        /* Tags used for cryptographic parameters. */
        case KM_TAG_PURPOSE:
        case KM_TAG_ALGORITHM:
        case KM_TAG_KEY_SIZE:
        case KM_TAG_BLOCK_MODE:
        case KM_TAG_DIGEST:
        case KM_TAG_MAC_LENGTH:
        case KM_TAG_PADDING:
        case KM_TAG_CHUNK_LENGTH:
        case KM_TAG_NONCE:
        case KM_TAG_RETURN_UNAUTHED:

        /* Tags not used for operations. */
        case KM_TAG_BLOB_USAGE_REQUIREMENTS:

        /* Algorithm specific parameters not used for access control. */
        case KM_TAG_RSA_PUBLIC_EXPONENT:

        /* Informational tags. */
        case KM_TAG_APPLICATION_DATA:
        case KM_TAG_CREATION_DATETIME:
        case KM_TAG_ORIGIN:
        case KM_TAG_ROLLBACK_RESISTANT:
        case KM_TAG_ROOT_OF_TRUST:

        /* Tag to provide data to operations. */
        case KM_TAG_ASSOCIATED_DATA:
            return_error = KM_ERROR_OK;
            break;
        default:
            // TODO(swillden): remove this default case.
            return_error = KM_ERROR_UNIMPLEMENTED;
            break;
        }

        if (return_error != KM_ERROR_OK) {
            return return_error;
        }
    }

    if ((tag_all_users_present && tag_user_id_present) ||
        (tag_user_auth_id_present && tag_no_auth_required_present) ||
        (tag_all_applications_present && tag_application_id_present)) {
        return_error = KM_ERROR_INVALID_TAG;
    }

    if (return_error == KM_ERROR_OK) {
        update_key_access_time(keyid);
    }

    return return_error;
}

keymaster_error_t KeymasterEnforcement::Active(const keymaster_key_param_t param,
                                               const time_t current_time) {
    time_t activation_time = param.date_time;
    if (difftime(current_time, activation_time) < 0) {
        return KM_ERROR_KEY_NOT_YET_VALID;
    }

    return KM_ERROR_OK;
}

keymaster_error_t KeymasterEnforcement::is_time_expired(const keymaster_key_param_t param,
                                                        const time_t current_time) {
    time_t expire_time = param.date_time;
    if (difftime(current_time, expire_time) > 0) {
        return KM_ERROR_KEY_EXPIRED;
    }
    return KM_ERROR_OK;
}

keymaster_error_t KeymasterEnforcement::UsageNotExpired(const keymaster_key_param_t param,
                                                        const time_t current_time,
                                                        const keymaster_purpose_t purpose) {
    switch (purpose) {
    case KM_PURPOSE_VERIFY:
    case KM_PURPOSE_DECRYPT:
        break;
    case KM_PURPOSE_SIGN:
    case KM_PURPOSE_ENCRYPT:
        return KM_ERROR_OK;
    }

    return is_time_expired(param, current_time);
}

keymaster_error_t KeymasterEnforcement::OriginationNotExpired(const keymaster_key_param_t param,
                                                              const time_t current_time,
                                                              const keymaster_purpose_t purpose) {
    switch (purpose) {
    case KM_PURPOSE_SIGN:
    case KM_PURPOSE_ENCRYPT:
        break;
    case KM_PURPOSE_DECRYPT:
    case KM_PURPOSE_VERIFY:
        return KM_ERROR_OK;
    }
    return is_time_expired(param, current_time);
}

keymaster_error_t KeymasterEnforcement::MinTimeBetweenOpsPassed(const keymaster_key_param_t param,
                                                                const km_id_t keyid,
                                                                const time_t current_time) {
    uint32_t min_time_between = param.integer;

    if (difftime(current_time, get_last_access_time(keyid)) < min_time_between) {
        return KM_ERROR_TOO_MANY_OPERATIONS;
    }
    return KM_ERROR_OK;
}

keymaster_error_t KeymasterEnforcement::NotUsedSinceBoot(const km_id_t keyid) {
    if (get_last_access_time(keyid) > -1) {
        return KM_ERROR_TOO_MANY_OPERATIONS;
    }
    return KM_ERROR_OK;
}

keymaster_error_t KeymasterEnforcement::UserAuthenticated(const keymaster_key_param_t param,
                                                          const uid_t uid) {
    uint32_t valid_user_id = param.integer;
    uint32_t user_id_to_test = get_user_id_from_uid(uid);

    if (valid_user_id == user_id_to_test) {
        return KM_ERROR_OK;
    } else {
        return KM_ERROR_INVALID_USER_ID;
    }
}

keymaster_error_t KeymasterEnforcement::AuthenticationIsFresh(const keymaster_key_param_t param,
                                                              const time_t current_time) const {
    time_t last_auth_time = get_last_auth_time();
    time_t required_time = param.integer;
    if (difftime(current_time, last_auth_time) > required_time) {
        return KM_ERROR_OK;
    } else {
        return KM_ERROR_KEY_USER_NOT_AUTHENTICATED;
    }
}

void KeymasterEnforcement::update_key_access_time(const km_id_t keyid) {
    accessTimeMap.update_key_access_time(keyid, get_current_time());
}

time_t KeymasterEnforcement::get_current_time() const {
    return time(NULL);
}

time_t KeymasterEnforcement::get_last_access_time(km_id_t keyid) {
    return accessTimeMap.last_key_access_time(keyid);
}

uint32_t KeymasterEnforcement::get_user_id_from_uid(uid_t uid) {
    uint32_t userId = uid / MULTIUSER_APP_PER_USER_RANGE;
    return userId;
}

time_t KeymasterEnforcement::get_last_auth_time() const {
    return last_auth_time;
}

void KeymasterEnforcement::UpdateUserAuthenticationTime() {
    last_auth_time = get_current_time();
}

bool KeymasterEnforcement::supported_purpose(const keymaster_purpose_t purpose) {
    switch (purpose) {
    case KM_PURPOSE_ENCRYPT:
    case KM_PURPOSE_DECRYPT:
    case KM_PURPOSE_SIGN:
    case KM_PURPOSE_VERIFY:
        return true;
        break;
    }
    return false;
}

bool KeymasterEnforcement::supported_purposes(const AuthorizationSet& auth_set) {
    int purpose_index;
    keymaster_purpose_t test_purpose;

    purpose_index = auth_set.find(KM_TAG_PURPOSE);
    for (; purpose_index >= 0; purpose_index = auth_set.find(KM_TAG_PURPOSE, purpose_index)) {
        test_purpose = static_cast<keymaster_purpose_t>(auth_set[purpose_index].enumerated);
        if (!supported_purpose(test_purpose)) {
            return false;
        }
    }

    return true;
}

keymaster_error_t KeymasterEnforcement::valid_purpose(const keymaster_purpose_t purpose,
                                                      const AuthorizationSet& auth_set) {
    if (!supported_purpose(purpose) || !supported_purposes(auth_set)) {
        return KM_ERROR_UNSUPPORTED_PURPOSE;
    }

    keymaster_purpose_t test_purpose;
    for (int purpose_index = auth_set.find(KM_TAG_PURPOSE); purpose_index >= 0;
         purpose_index = auth_set.find(KM_TAG_PURPOSE, purpose_index)) {
        test_purpose = static_cast<keymaster_purpose_t>(auth_set[purpose_index].enumerated);
        if (test_purpose == purpose) {
            return KM_ERROR_OK;
        }
    }

    return KM_ERROR_INCOMPATIBLE_PURPOSE;
}

KeymasterEnforcement::AccessTimeMap::AccessTimeMap() {
}

List<access_time_struct>::iterator KeymasterEnforcement::AccessTimeMap::find(uint32_t key_index) {
    List<access_time_struct>::iterator posn;

    posn = last_access_list.begin();
    for (; (*posn).keyid != key_index && posn != last_access_list.end(); posn++) {
    }
    return posn;
}

void KeymasterEnforcement::AccessTimeMap::update_key_access_time(uint32_t key_index,
                                                                 time_t current_time) {
    List<access_time_struct>::iterator posn;

    posn = find(key_index);
    if (posn != last_access_list.end()) {
        (*posn).access_time = current_time;
    } else {
        access_time_struct ac;
        ac.keyid = key_index;
        ac.access_time = current_time;
        last_access_list.push_front(ac);
    }
}

time_t KeymasterEnforcement::AccessTimeMap::last_key_access_time(uint32_t key_index) {
    List<access_time_struct>::iterator posn;

    posn = find(key_index);
    if (posn != last_access_list.end()) {
        return (*posn).access_time;
    }
    return -1;
}

}; /* namespace keymaster */
