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

/*
 * sdk 配置文件
 */

#define CONFIG_CLOUD_ENABLED               1   //是否使能IntoYun云通讯接口
#define CONFIG_CLOUD_DATAPOINT_ENABLED     1   //是否使能数据点通讯接口
#define CONFIG_CLOUD_OTA_ENABLED           1   //是否使能固件升级通讯接口
#define CONFIG_CLOUD_CHANNEL               1   //选择云端通讯通道  1: MQTT  2: COAP

// 云端通讯安全模式
// 通道 + 认证 + 数据组织加密方式
// 1. TCP + Guider + formCrypto
// 2. TCP + Guider + formPlain
// 3. TLS + Guider + Plain
#define CONFIG_CLOUD_SECURE_MODE           1   //云端通讯安全模式

#define CONFIG_MQTT_ENABLED                1   //是否使能MQTT功能
#define CONFIG_COAP_ENABLED                1   //是否使能COAP功能

#define CONFIG_KEY_ENABLE                  1   //是否按键接口功能
#define CONFIG_TIMER_ENABLE                1   //是否定时器接口功能

#define CONFIG_LOG_ENABLE                  1   //是否使能日志功能

#define CONFIG_LOG_DEFAULT_LEVEL           1
#define CONFIG_LOG_DEFAULT_LEVEL_ERROR     1
