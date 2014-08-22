/*
 * Copyright 2014 The Android Open Source Project
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
#include <stdio.h>
#include <stdlib.h>

#include "common/ote_nv_uuid.h"
#include "common/ote_command.h"
#include "client/ote_client.h"

#include "trusty_keymaster_lib.h"

te_error_t trusty_init(void** opaque_session) {
    te_operation_t operation;
    te_service_id_t uuid = SERVICE_KEYMASTER_UUID;
    te_session_t* session;
    int err;

    session = malloc(sizeof(te_session_t));
    if (session == NULL)
        return OTE_ERROR_OUT_OF_MEMORY;

    te_init_operation(&operation);
    err = te_open_session(session, &uuid, &operation);
    if (err != OTE_SUCCESS)
        return err;

    *opaque_session = session;
    return OTE_SUCCESS;
}

void trusty_deinit(void* opaque_session) {
    if (opaque_session == NULL)
        return;
    te_close_session(opaque_session);
    free(opaque_session);
}

te_error_t trusty_call(void* session, uint32_t cmd, void* in_buf, uint32_t in_size, void* out_buf,
                       uint32_t* out_size) {
    te_operation_t operation;
    int err;

    te_init_operation(&operation);

    te_oper_set_param_mem_ro(&operation, 0, in_buf, in_size);
    te_oper_set_param_mem_rw(&operation, 1, out_buf, *out_size);
    te_oper_set_param_int_rw(&operation, 2, *out_size);
    te_oper_set_command(&operation, cmd);
    err = te_launch_operation(session, &operation);
    if (err != OTE_SUCCESS) {
        printf("ERROR: te_launch_operation failed.\n");
        return err;
    }

    te_oper_get_param_int(&operation, 2, out_size);
    return OTE_SUCCESS;
}
