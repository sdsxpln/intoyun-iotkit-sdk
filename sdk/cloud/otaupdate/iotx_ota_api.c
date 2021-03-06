/*
 * Copyright (c) 2013-2018 Molmc Group. All rights reserved.
 * License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <stdio.h>
#include <stdlib.h>

#include "lite-log.h"
#include "iotx_ota_api.h"
#include "iotx_comm_if_api.h"

#include "iotx_ota_lib.c"
#include "iotx_ota_fetch.c"

typedef struct  {
    IOT_OTA_State_t state;         /* OTA state */
    uint8_t type_file;                  /* firmware type */
    char *purl;                    /* point to URL */
    char *pmd5;                    /* point to MD5 */
    uint32_t size_last_fetched;    /* size of last downloaded */
    uint32_t size_fetched;         /* size of already downloaded */
    uint32_t size_file;            /* size of file */
    int err;                       /* last error code */
    void *md5;                     /* MD5 handle */
    void *ch_fetch;                /* channel handle of download */
    THandlerFunction_Progress cb;  /* progress callback */
} OTA_Struct_t, *OTA_Struct_pt;


/* Initialize OTA module */
void *IOT_OTA_Init(uint8_t fileType, const char *url, const char *md5, uint32_t size)
{
    OTA_Struct_pt h_ota = NULL;

    if ((NULL == url) || (NULL == md5)) {
        log_err("one or more parameters is invalid");
        return NULL;
    }

    log_info("type : %d", fileType);
    log_info("url  : %s", url);
    log_info("md5  : %s", md5);
    log_info("size : %d", size);

    if (NULL == (h_ota = HAL_Malloc(sizeof(OTA_Struct_t)))) {
        log_err("allocate failed");
        return NULL;
    }
    memset(h_ota, 0, sizeof(OTA_Struct_t));
    h_ota->state = IOT_OTAS_UNINITED;

    if (NULL == (h_ota->purl = HAL_Malloc(strlen(url) + 1))) {
        log_err("allocate url failed");
        goto do_exit;
    }

    if (NULL == (h_ota->pmd5 = HAL_Malloc(strlen(md5) + 1))) {
        log_err("allocate md5 failed");
        goto do_exit;
    }
    strcpy(h_ota->purl, url);
    strcpy(h_ota->pmd5, md5);
    h_ota->size_file = size;
    h_ota->md5 = otalib_MD5Init();
    if (NULL == h_ota->md5) {
        log_err("initialize md5 failed");
        goto do_exit;
    }

    if (NULL == (h_ota->ch_fetch = ofc_Init(h_ota->purl))) {
        log_err("Initialize fetch module failed");
        goto do_exit;
    }

    h_ota->state = IOT_OTAS_INITED;
    return h_ota;

do_exit:

    if (NULL != h_ota->purl) {
        HAL_Free(h_ota->purl);
    }

    if (NULL != h_ota->pmd5) {
        HAL_Free(h_ota->pmd5);
    }

    if (NULL != h_ota->md5) {
        otalib_MD5Deinit(h_ota->md5);
    }

    if (NULL != h_ota->ch_fetch) {
        ofc_Deinit(h_ota->ch_fetch);
    }

    if (NULL != h_ota) {
        HAL_Free(h_ota);
    }

    return NULL;
}

/* deinitialize OTA module */
int IOT_OTA_Deinit(void *handle)
{
    OTA_Struct_pt h_ota = (OTA_Struct_pt) handle;

    if (NULL == h_ota) {
        log_err("handle is NULL");
        return IOT_OTAE_INVALID_PARAM;
    }

    if (IOT_OTAS_UNINITED == h_ota->state) {
        log_err("handle is uninitialized");
        h_ota->err = IOT_OTAE_INVALID_STATE;
        return -1;
    }

    HAL_Free(h_ota->purl);
    HAL_Free(h_ota->pmd5);
    otalib_MD5Deinit(h_ota->md5);
    ofc_Deinit(h_ota->ch_fetch);
    HAL_Free(h_ota);
    return 0;
}

int IOT_OTA_SetProgressCallback(void *handle, THandlerFunction_Progress fn)
{
    OTA_Struct_pt h_ota = (OTA_Struct_pt) handle;

    if (NULL == h_ota) {
        log_err("handle is NULL");
        return IOT_OTAE_INVALID_PARAM;
    }

    if (IOT_OTAS_UNINITED == h_ota->state) {
        log_err("handle is uninitialized");
        h_ota->err = IOT_OTAE_INVALID_STATE;
        return -1;
    }

    h_ota->cb = fn;
    return 0;
}

bool IOT_OTA_Update(void *handle)
{
#define OTA_BUF_LEN        (1500)
    int ret;
    int ok = false;
    char buf[OTA_BUF_LEN];
    OTA_Struct_pt h_ota = (OTA_Struct_pt) handle;

    if (NULL == handle) {
        log_err("invalid parameter");
        goto do_exit;
    }

    do {
        ret = ofc_Fetch(h_ota->ch_fetch, buf, OTA_BUF_LEN, 1);
        if (ret < 0) {
            log_err("Fetch firmware failed");
            h_ota->state = IOT_OTAS_FETCHED;
            h_ota->err = IOT_OTAE_FETCH_FAILED;
            break;
        } else if (0 == h_ota->size_fetched) {
            /* force report status in the first */
            h_ota->cb(h_ota, NULL, 0, 0, h_ota->size_file);
        }

        h_ota->size_last_fetched = ret;
        h_ota->size_fetched += ret;

        otalib_MD5Update(h_ota->md5, buf, ret);

        h_ota->cb(h_ota, (uint8_t *)buf, ret, h_ota->size_fetched, h_ota->size_file);
        if (h_ota->size_fetched >= h_ota->size_file) {
            char md5_str[33];
            otalib_MD5Finalize(h_ota->md5, md5_str);
            log_debug("origin=%s, now=%s", h_ota->pmd5, md5_str);
            if (0 == strcmp(h_ota->pmd5, md5_str)) {
                ok = true;
                h_ota->err = IOT_OTAE_NONE;
            } else {
                h_ota->err = IOT_OTAE_CHECK_FAILED;
            }
            h_ota->state = IOT_OTAS_FETCHED;
            break;
        }
        IOT_Comm_Yield();
    } while(1);

do_exit:
    if(ok) {
        IOT_OTA_ReportProgress(h_ota, IOTX_OTA_REPLY_FETCH_SUCCESS, 0);
    } else {
        IOT_OTA_ReportProgress(h_ota, IOTX_OTA_REPLY_FETCH_FAILED, 0);
    }
    return ok;
#undef OTA_BUF_LEN
}

int IOT_OTA_ReportProgress(void *handle, iotx_ota_reply_t reply, uint8_t progress)
{
    OTA_Struct_pt h_ota = (OTA_Struct_pt) handle;

    if (NULL == h_ota) {
        log_err("handle is NULL");
        return IOT_OTAE_INVALID_PARAM;
    }

    if (IOT_OTAS_UNINITED == h_ota->state) {
        log_err("handle is uninitialized");
        h_ota->err = IOT_OTAE_INVALID_STATE;
        return -1;
    }

    return IOT_Comm_SendActionReply(h_ota->type_file, reply, progress);
}

/* Get last error code */
int IOT_OTA_GetLastError(void *handle)
{
    OTA_Struct_pt h_ota = (OTA_Struct_pt) handle;

    if (NULL == handle) {
        log_err("handle is NULL");
        return  IOT_OTAE_INVALID_PARAM;
    }

    return h_ota->err;
}

