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

#ifndef _OTA_LIB_C_
#define _OTA_LIB_C_

#include <stdio.h>
#include "iot_export_ota.h"
#include "iot_import_ota.h"
#include "iotx_ota_internal.h"


static const char *otalib_JsonValueOf(const char *json, uint32_t json_len, const char *key, uint32_t *val_len)
{
    /*
    int length;
    const char *val;
    val = json_get_value_by_name((char *)json, json_len, (char *)key, &length, NULL);
    if (NULL != val) {
        *val_len = (uint32_t) length;
    }
    return val;
    */
    return NULL;
}

static void *otalib_MD5Init(void)
{
    iot_md5_context *ctx = HAL_Malloc(sizeof(iot_md5_context));
    if (NULL == ctx) {
        return NULL;
    }

    utils_md5_init(ctx);
    utils_md5_starts(ctx);

    return ctx;
}

static void otalib_MD5Update(void *md5, const char *buf, size_t buf_len)
{
    utils_md5_update(md5, (unsigned char *)buf, buf_len);
}

static void otalib_MD5Finalize(void *md5, char *output_str)
{
    int i;
    unsigned char buf_out[16];
    utils_md5_finish(md5, buf_out);

    for (i = 0; i < 16; ++i) {
        output_str[i * 2] = utils_hb2hex(buf_out[i] >> 4);
        output_str[i * 2 + 1] = utils_hb2hex(buf_out[i]);
    }
    output_str[32] = '\0';
}

static void otalib_MD5Deinit(void *md5)
{
    if (NULL != md5) {
        HAL_Free(md5);
    }
}

/* Get the specific @key value, and copy to @dest */
/* 0, successful; -1, failed */
static int otalib_GetFirmwareFixlenPara(const char *json_doc,
                                        size_t json_doc_len,
                                        const char *key,
                                        char *dest,
                                        size_t dest_len)
{
    const char *pvalue;
    uint32_t val_len;

    if (NULL == (pvalue = otalib_JsonValueOf(json_doc, json_doc_len, key, &val_len))) {
        MOLMC_LOGE("ota", "Not '%s' key in json doc of OTA", key);
        return -1;
    }

    if (val_len > dest_len) {
        MOLMC_LOGE("ota", "value length of the key is too long");
        return -1;
    }

    memcpy(dest, pvalue, val_len);

    return 0;
}


/* Get variant length parameter of firmware, and copy to @dest */
/* 0, successful; -1, failed */
static int otalib_GetFirmwareVarlenPara(const char *json_doc,
                                        size_t json_doc_len,
                                        const char *key,
                                        char **dest)
{
    const char *pvalue;
    uint32_t val_len;

    if (NULL == (pvalue = otalib_JsonValueOf(json_doc, json_doc_len, key, &val_len))) {
        MOLMC_LOGE("ota", "Not %s key in json doc of OTA", key);
        return -1;
    }

    if (NULL == (*dest = HAL_Malloc(val_len + 1))) {
        MOLMC_LOGE("ota", "allocate for dest failed");
        return -1;
    }

    memcpy(*dest, pvalue, val_len);
    (*dest)[val_len] = '\0';

    return 0;
}


int otalib_GetParams(const char *json_doc, uint32_t json_len, char **url, char **version, char *md5,
                     uint32_t *file_size)
{
#define OTA_FILESIZE_STR_LEN    (16)
    char file_size_str[OTA_FILESIZE_STR_LEN + 1];

    /* get version */
    if (0 != otalib_GetFirmwareVarlenPara(json_doc, json_len, "version", version)) {
        MOLMC_LOGE("ota", "get value of version key failed");
        return -1;
    }

    /* get URL */
    if (0 != otalib_GetFirmwareVarlenPara(json_doc, json_len, "url", url)) {
        MOLMC_LOGE("ota", "get value of url key failed");
        return -1;
    }

    /* get md5 */
    if (0 != otalib_GetFirmwareFixlenPara(json_doc, json_len, "md5", md5, 32)) {
        MOLMC_LOGE("ota", "get value of md5 key failed");
        return -1;
    }

    /* get file size */
    if (0 != otalib_GetFirmwareFixlenPara(json_doc, json_len, "size", file_size_str, OTA_FILESIZE_STR_LEN)) {
        MOLMC_LOGE("ota", "get value of size key failed");
        return -1;
    }
    file_size_str[OTA_FILESIZE_STR_LEN] = '\0';
    *file_size = atoi(file_size_str);

    return 0;

#undef OTA_FILESIZE_STR_LEN
}


/* Generate firmware information according to @id, @version */
/* and then copy to @buf. */
/* 0, successful; -1, failed */
int otalib_GenInfoMsg(char *buf, size_t buf_len, uint32_t id, const char *version)
{
    int ret;
    ret = HAL_Snprintf(buf,
                       buf_len,
                       "{\"id\":%d,\"params\":{\"version\":\"%s\"}}",
                       id,
                       version);

    if (ret < 0) {
        MOLMC_LOGE("ota", "HAL_Snprintf failed");
        return -1;
    }

    return 0;
}


/* Generate report information according to @id, @msg */
/* and then copy to @buf. */
/* 0, successful; -1, failed */
int otalib_GenReportMsg(char *buf, size_t buf_len, uint32_t id, int progress, const char *msg_detail)
{
    int ret;
    if (NULL == msg_detail) {
        ret = HAL_Snprintf(buf,
                           buf_len,
                           "{\"id\":%d,\"params\": {\"step\": \"%d\"}}",
                           id,
                           progress);
    } else {
        ret = HAL_Snprintf(buf,
                           buf_len,
                           "{\"id\":%d,\"params\": {\"step\": \"%d\",\"desc\":\"%s\"}}",
                           id,
                           progress,
                           msg_detail);
    }


    if (ret < 0) {
        MOLMC_LOGE("ota", "HAL_Snprintf failed");
        return -1;
    } else if (ret >= buf_len) {
        MOLMC_LOGE("ota", "msg is too long");
        return IOT_OTAE_STR_TOO_LONG;
    }

    return 0;
}


#endif /* _OTA_LIB_C_ */
