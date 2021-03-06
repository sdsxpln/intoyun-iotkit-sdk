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

#ifndef __HAL_UDP_INTERFACE_H__
#define __HAL_UDP_INTERFACE_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "hal_import.h"

#define NETWORK_ADDR_LEN      (16)

void *HAL_UDP_create(char *host, unsigned short port);
void HAL_UDP_close(void *p_socket);
int HAL_UDP_write(void *p_socket, const unsigned char *p_data, unsigned int datalen);
int HAL_UDP_read(void *p_socket, unsigned char *p_data, unsigned int datalen);
int HAL_UDP_readTimeout(void *p_socket, unsigned char *p_data, unsigned int datalen, unsigned int timeout);

#ifdef __cplusplus
}
#endif

#endif

