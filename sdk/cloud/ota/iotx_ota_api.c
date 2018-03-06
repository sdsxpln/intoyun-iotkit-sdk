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

#include "iot_import.h"
#include "iot_import_ota.h"
#include "iotx_ota_internal.h"
#include "utils_httpc.h"
#include "lite-utils.h"


#include "iotx_ota_lib.c"

#if CONFIG_CLOUD_CHANNEL == 1     //MQTT
#include "iotx_ota_mqtt.c"
#elif CONFIG_CLOUD_CHANNEL == 2   //COAP
#include "iotx_ota_coap.c"
#else
#include "iotx_ota_mqtt.c"
//#error "NOT support yet!"
#endif

#include "iotx_ota_fetch.c"

typedef struct  {
    const char *product_key;    /* point to product key */
    const char *device_name;    /* point to device name */

    uint32_t id;                /* message id */
    IOT_OTA_State_t state;      /* OTA state */
    uint32_t size_last_fetched; /* size of last downloaded */
    uint32_t size_fetched;      /* size of already downloaded */
    uint32_t size_file;         /* size of file */
    char *purl;                 /* point to URL */
    char *version;              /* point to string */
    char md5sum[33];            /* MD5 string */

    void *md5;                  /* MD5 handle */
    void *ch_signal;            /* channel handle of signal exchanged with OTA server */
    void *ch_fetch;             /* channel handle of download */

    int err;                    /* last error code */

} OTA_Struct_t, *OTA_Struct_pt;


/* check whether the progress state is valid or not */
/* return: true, valid progress state; false, invalid progress state. */
static int ota_check_progress(IOT_OTA_Progress_t progress)
{
    return ((progress >= IOT_OTAP_BURN_FAILED)
            && (progress <= IOT_OTAP_FETCH_PERCENTAGE_MAX));
}


static void ota_callback(void *pcontext, const char *msg, uint32_t msg_len)
{
    const char *pvalue;
    uint32_t val_len;

    OTA_Struct_pt h_ota = (OTA_Struct_pt) pcontext;

    if (h_ota->state >= IOT_OTAS_FETCHING) {
        MOLMC_LOGI("ota", "In downloading or downloaded state");
        return;
    }

    pvalue = otalib_JsonValueOf(msg, msg_len, "message", &val_len);
    if (NULL == pvalue) {
        MOLMC_LOGE("ota", "invalid json doc of OTA ");
        return;
    }

    /* check whether is positive message */
    if (!((strlen("success") == val_len) && (0 == strncmp(pvalue, "success", val_len)))) {
        MOLMC_LOGE("ota", "fail state of json doc of OTA");
        return ;
    }

    /* get value of 'data' key */
    pvalue = otalib_JsonValueOf(msg, msg_len, "data", &val_len);
    if (NULL == pvalue) {
        MOLMC_LOGE("ota", "Not 'data' key in json doc of OTA");
        return;
    }

    if (0 != otalib_GetParams(pvalue, val_len, &h_ota->purl, &h_ota->version, h_ota->md5sum, &h_ota->size_file)) {
        MOLMC_LOGE("ota", "Get firmware parameter failed");
        return;
    }

    if (NULL == (h_ota->ch_fetch = ofc_Init(h_ota->purl))) {
        MOLMC_LOGE("ota", "Initialize fetch module failed");
        return ;
    }

    h_ota->state = IOT_OTAS_FETCHING;
}


/* Initialize OTA module */
void *IOT_OTA_Init(const char *product_key, const char *device_name, void *ch_signal)
{
    OTA_Struct_pt h_ota = NULL;

    if ((NULL == product_key) || (NULL == device_name) || (NULL == ch_signal)) {
        MOLMC_LOGE("ota", "one or more parameters is invalid");
        return NULL;
    }

    if (NULL == (h_ota = HAL_Malloc(sizeof(OTA_Struct_t)))) {
        MOLMC_LOGE("ota", "allocate failed");
        return NULL;
    }
    memset(h_ota, 0, sizeof(OTA_Struct_t));
    h_ota->state = IOT_OTAS_UNINITED;

    h_ota->ch_signal = osc_Init(product_key, device_name, ch_signal, ota_callback, h_ota);
    if (NULL == h_ota->ch_signal) {
        MOLMC_LOGE("ota", "initialize signal channel failed");
        goto do_exit;
    }

    h_ota->md5 = otalib_MD5Init();
    if (NULL == h_ota->md5) {
        MOLMC_LOGE("ota", "initialize md5 failed");
        goto do_exit;
    }

    h_ota->product_key = product_key;
    h_ota->device_name = device_name;
    h_ota->state = IOT_OTAS_INITED;
    return h_ota;

do_exit:

    if (NULL != h_ota->ch_signal) {
        osc_Deinit(h_ota->ch_signal);
    }

    if (NULL != h_ota->md5) {
        otalib_MD5Deinit(h_ota->md5);
    }

    if (NULL != h_ota) {
        HAL_Free(h_ota);
    }

    return NULL;

#undef AOM_INFO_MSG_LEN
}


/* deinitialize OTA module */
int IOT_OTA_Deinit(void *handle)
{
    OTA_Struct_pt h_ota = (OTA_Struct_pt) handle;

    if (NULL == h_ota) {
        MOLMC_LOGE("ota", "handle is NULL");
        return IOT_OTAE_INVALID_PARAM;
    }

    if (IOT_OTAS_UNINITED == h_ota->state) {
        MOLMC_LOGE("ota", "handle is uninitialized");
        h_ota->err = IOT_OTAE_INVALID_STATE;
        return -1;
    }

    osc_Deinit(h_ota->ch_signal);
    ofc_Deinit(h_ota->ch_fetch);
    otalib_MD5Deinit(h_ota->md5);

    if (NULL != h_ota->purl) {
        HAL_Free(h_ota->purl);
    }

    if (NULL != h_ota->version) {
        HAL_Free(h_ota->version);
    }

    HAL_Free(h_ota);
    return 0;
}


#define OTA_VERSION_STR_LEN_MIN     (1)
#define OTA_VERSION_STR_LEN_MAX     (32)

int IOT_OTA_ReportVersion(void *handle, const char *version)
{
#define MSG_INFORM_LEN  (128)

    int ret, len;
    char *msg_informed;
    OTA_Struct_pt h_ota = (OTA_Struct_pt) handle;

    if ((NULL == h_ota) || (NULL == version)) {
        MOLMC_LOGE("ota", "one or more invalid parameter");
        return IOT_OTAE_INVALID_PARAM;
    }

    len = strlen(version);
    if ((len < OTA_VERSION_STR_LEN_MIN) || (len > OTA_VERSION_STR_LEN_MAX)) {
        MOLMC_LOGE("ota", "version string is invalid: must be [1, 32] chars");
        h_ota->err = IOT_OTAE_INVALID_PARAM;
        return -1;
    }

    if (IOT_OTAS_UNINITED == h_ota->state) {
        MOLMC_LOGE("ota", "handle is uninitialized");
        h_ota->err = IOT_OTAE_INVALID_STATE;
        return -1;
    }

    if (NULL == (msg_informed = HAL_Malloc(MSG_INFORM_LEN))) {
        MOLMC_LOGE("ota", "allocate for msg_informed failed");
        h_ota->err = IOT_OTAE_NOMEM;
        return -1;
    }

    ret = otalib_GenInfoMsg(msg_informed, MSG_INFORM_LEN, h_ota->id, version);
    if (ret != 0) {
        MOLMC_LOGE("ota", "generate inform message failed");
        h_ota->err = ret;
        ret = -1;
        goto do_exit;
    }

    ret = osc_ReportVersion(h_ota->ch_signal, msg_informed);
    if (0 != ret) {
        MOLMC_LOGE("ota", "Report version failed");
        h_ota->err = ret;
        ret = -1;
        goto do_exit;
    }
    ret = 0;

do_exit:
    if (NULL != msg_informed) {
        HAL_Free(msg_informed);
    }
    return ret;

#undef MSG_INFORM_LEN
}


int IOT_OTA_ReportProgress(void *handle, IOT_OTA_Progress_t progress, const char *msg)
{
#define MSG_REPORT_LEN  (256)

    int ret = -1;
    char *msg_reported;
    OTA_Struct_pt h_ota = (OTA_Struct_pt) handle;

    if (NULL == handle) {
        MOLMC_LOGE("ota", "handle is NULL");
        return IOT_OTAE_INVALID_PARAM;
    }

    if (IOT_OTAS_UNINITED == h_ota->state) {
        MOLMC_LOGE("ota", "handle is uninitialized");
        h_ota->err = IOT_OTAE_INVALID_STATE;
        return -1;
    }

    if (!ota_check_progress(progress)) {
        MOLMC_LOGE("ota", "progress is a invalid parameter");
        h_ota->err = IOT_OTAE_INVALID_PARAM;
        return -1;
    }

    if (NULL == (msg_reported = HAL_Malloc(MSG_REPORT_LEN))) {
        MOLMC_LOGE("ota", "allocate for msg_reported failed");
        h_ota->err = IOT_OTAE_NOMEM;
        return -1;
    }

    ret = otalib_GenReportMsg(msg_reported, MSG_REPORT_LEN, h_ota->id, progress, msg);
    if (0 != ret) {
        MOLMC_LOGE("ota", "generate reported message failed");
        h_ota->err = ret;
        goto do_exit;
    }

    ret = osc_ReportProgress(h_ota->ch_signal, msg_reported);
    if (0 != ret) {
        MOLMC_LOGE("ota", "Report progress failed");
        h_ota->err = ret;
        goto do_exit;
    }

    ret = 0;

do_exit:
    if (NULL != msg_reported) {
        HAL_Free(msg_reported);
    }
    return ret;

#undef MSG_REPORT_LEN
}


/* check whether is downloading */
int IOT_OTA_IsFetching(void *handle)
{
    OTA_Struct_pt h_ota = (OTA_Struct_pt)handle;

    if (NULL == handle) {
        MOLMC_LOGE("ota", "handle is NULL");
        return 0;
    }

    if (IOT_OTAS_UNINITED == h_ota->state) {
        MOLMC_LOGE("ota", "handle is uninitialized");
        h_ota->err = IOT_OTAE_INVALID_STATE;
        return 0;
    }

    return (IOT_OTAS_FETCHING == h_ota->state);
}


/* check whether fetch over */
int IOT_OTA_IsFetchFinish(void *handle)
{
    OTA_Struct_pt h_ota = (OTA_Struct_pt) handle;

    if (NULL == handle) {
        MOLMC_LOGE("ota", "handle is NULL");
        return 0;
    }

    if (IOT_OTAS_UNINITED == h_ota->state) {
        MOLMC_LOGE("ota", "handle is uninitialized");
        h_ota->err = IOT_OTAE_INVALID_STATE;
        return 0;
    }

    return (IOT_OTAS_FETCHED == h_ota->state);
}


int IOT_OTA_FetchYield(void *handle, char *buf, uint32_t buf_len, uint32_t timeout_ms)
{
    int ret;
    OTA_Struct_pt h_ota = (OTA_Struct_pt) handle;

    if ((NULL == handle) || (NULL == buf) || (0 == buf_len)) {
        MOLMC_LOGE("ota", "invalid parameter");
        return IOT_OTAE_INVALID_PARAM;
    }

    if (IOT_OTAS_FETCHING != h_ota->state) {
        h_ota->err = IOT_OTAE_INVALID_STATE;
        return IOT_OTAE_INVALID_STATE;
    }

    ret = ofc_Fetch(h_ota->ch_fetch, buf, buf_len, timeout_ms);
    if (ret < 0) {
        MOLMC_LOGE("ota", "Fetch firmware failed");
        h_ota->state = IOT_OTAS_FETCHED;
        h_ota->err = IOT_OTAE_FETCH_FAILED;
        return -1;
    } else if (0 == h_ota->size_fetched) {
        /* force report status in the first */
        IOT_OTA_ReportProgress(h_ota, IOT_OTAP_FETCH_PERCENTAGE_MIN, "Enter in downloading state");
    }

    h_ota->size_last_fetched = ret;
    h_ota->size_fetched += ret;

    if (h_ota->size_fetched >= h_ota->size_file) {
        h_ota->state = IOT_OTAS_FETCHED;
    }

    otalib_MD5Update(h_ota->md5, buf, ret);

    return ret;
}


int IOT_OTA_Ioctl(void *handle, IOT_OTA_CmdType_t type, void *buf, size_t buf_len)
{
    OTA_Struct_pt h_ota = (OTA_Struct_pt) handle;

    if ((NULL == handle) || (NULL == buf) || (0 == buf_len)) {
        MOLMC_LOGE("ota", "invalid parameter");
        return IOT_OTAE_INVALID_PARAM;
    }

    if (h_ota->state < IOT_OTAS_FETCHING) {
        h_ota->err = IOT_OTAE_INVALID_STATE;
        return IOT_OTAE_INVALID_STATE;
    }

    switch (type) {
        case IOT_OTAG_FETCHED_SIZE:
            if ((4 != buf_len) || (0 != ((unsigned long)buf & 0x3))) {
                MOLMC_LOGE("ota", "Invalid parameter");
                h_ota->err = IOT_OTAE_INVALID_PARAM;
                return -1;
            } else {
                *((uint32_t *)buf) = h_ota->size_fetched;
                return 0;
            }

        case IOT_OTAG_FILE_SIZE:
            if ((4 != buf_len) || (0 != ((unsigned long)buf & 0x3))) {
                MOLMC_LOGE("ota", "Invalid parameter");
                h_ota->err = IOT_OTAE_INVALID_PARAM;
                return -1;
            } else {
                *((uint32_t *)buf) = h_ota->size_file;
                return 0;
            };

        case IOT_OTAG_VERSION:
            strncpy(buf, h_ota->version, buf_len);
            ((char *)buf)[buf_len - 1] = '\0';
            break;

        case IOT_OTAG_MD5SUM:
            strncpy(buf, h_ota->md5sum, buf_len);
            ((char *)buf)[buf_len - 1] = '\0';
            break;

        case IOT_OTAG_CHECK_FIRMWARE:
            if ((4 != buf_len) || (0 != ((unsigned long)buf & 0x3))) {
                MOLMC_LOGE("ota", "Invalid parameter");
                h_ota->err = IOT_OTAE_INVALID_PARAM;
                return -1;
            } else if (h_ota->state != IOT_OTAS_FETCHED) {
                h_ota->err = IOT_OTAE_INVALID_STATE;
                MOLMC_LOGE("ota", "Firmware can be checked in IOT_OTAS_FETCHED state only");
                return -1;
            } else {
                char md5_str[33];
                otalib_MD5Finalize(h_ota->md5, md5_str);
                MOLMC_LOGD("ota", "origin=%s, now=%s", h_ota->md5sum, md5_str);
                if (0 == strcmp(h_ota->md5sum, md5_str)) {
                    *((uint32_t *)buf) = 1;
                } else {
                    *((uint32_t *)buf) = 0;
                }
                return 0;
            }

        default:
            MOLMC_LOGE("ota", "invalid cmd type");
            h_ota->err = IOT_OTAE_INVALID_PARAM;
            return -1;
    }

    return 0;
}


/* Get last error code */
int IOT_OTA_GetLastError(void *handle)
{
    OTA_Struct_pt h_ota = (OTA_Struct_pt) handle;

    if (NULL == handle) {
        MOLMC_LOGE("ota", "handle is NULL");
        return  IOT_OTAE_INVALID_PARAM;
    }

    return h_ota->err;
}

