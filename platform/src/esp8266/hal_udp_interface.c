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

#include <errno.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <pthread.h>

#include "hal_import.h"

void *HAL_UDP_create(char *host, unsigned short port)
{
    return NULL;
}

void HAL_UDP_close(void *p_socket)
{
}

int HAL_UDP_write(void *p_socket, const unsigned char *p_data, unsigned int datalen)
{
    return -1;
}

int HAL_UDP_read(void *p_socket, unsigned char *p_data, unsigned int datalen)
{
    return -1;
}

int HAL_UDP_readTimeout(void *p_socket, unsigned char *p_data, unsigned int datalen, unsigned int timeout)
{
    return -1;
}

int HAL_UDP_resolveAddress(const char *p_host,  char addr[NETWORK_ADDR_LEN])
{
    return 0;
}

