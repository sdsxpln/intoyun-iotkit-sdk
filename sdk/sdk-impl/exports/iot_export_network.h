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

#ifndef __IOT_EXPORT_NETWORK_H__
#define __IOT_EXPORT_NETWORK_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "iotx_comm_if_api.h"

typedef struct
{
    bool (*connected)(void);
    int (*setState)(iotx_network_state_t state);
} iot_network_if_t;

extern const iot_network_if_t Network;

#ifdef __cplusplus
}
#endif

#endif

