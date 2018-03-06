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

#ifndef __IOT_IMPORT_OTA_H__
#define __IOT_IMPORT_OTA_H__

#include "iot_import.h"
#include "sdkconfig.h"
#include "lite-log.h"
#include "json_parser.h"
#include "utils_md5.h"

#define OTA_MALLOC          HAL_Malloc
#define OTA_FREE            HAL_Free
#define OTA_LOG_DEBUG       log_debug
#define OTA_LOG_INFO        log_info
#define OTA_LOG_ERROR       log_err
#define OTA_ASSERT          LITE_ASSERT
#define OTA_SNPRINTF        HAL_Snprintf

#endif /* _IOT_IMPORT_OTA_H_ */

