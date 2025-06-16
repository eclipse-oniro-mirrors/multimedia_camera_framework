/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <map>
#include "camera_log.h"
#include "qos.h"
#include "common/qos_utils.h"

namespace OHOS {
namespace CameraStandard {

static const std::map<QOS::QosLevel, uv_qos_t> qosLevelToUvQosMap = {
    {QOS::QosLevel::QOS_USER_INITIATED, uv_qos_t::uv_qos_user_initiated},
    {QOS::QosLevel::QOS_DEADLINE_REQUEST, uv_qos_t::uv_qos_reserved},
    {QOS::QosLevel::QOS_USER_INTERACTIVE, uv_qos_t::uv_qos_user_interactive},
};

uv_qos_t QosUtils::GetUvWorkQos()
{
    QOS::QosLevel level;
    GetThreadQos(level);
    auto it = qosLevelToUvQosMap.find(level);
    CHECK_ERROR_RETURN_RET(it != qosLevelToUvQosMap.end(), it->second);
    return uv_qos_t::uv_qos_user_initiated;
}
} // namespace CameraStandard
} // namespace OHOS