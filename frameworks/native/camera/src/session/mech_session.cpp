/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

#include "session/mech_session.h"

#include "camera_error_code.h"
#include "camera_log.h"
#include "camera_util.h"

namespace OHOS {
namespace CameraStandard {
MechSession::MechSession()
{
    MEDIA_DEBUG_LOG("%{public}s is called!", __FUNCTION__);
}

MechSession::~MechSession()
{
    MEDIA_DEBUG_LOG("%{public}s is called!", __FUNCTION__);
}

int32_t MechSession::EnableMechDelivery(bool isEnableMech)
{
    return CameraErrorCode::SUCCESS;
}

void MechSession::SetCallback(std::shared_ptr<MechSessionCallback> callback)
{
}

std::shared_ptr<MechSessionCallback> MechSession::GetCallback()
{
    return nullptr;
}

int32_t MechSession::Release()
{
    return CameraErrorCode::SUCCESS;
}
} // namespace CameraStandard
} // namespace OHOS