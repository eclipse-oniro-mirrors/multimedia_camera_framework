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

#include "camera_strategy.h"

#include "dps_event_report.h"
#include "events_info.h"
#include "events_monitor.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
namespace {
    constexpr char COMMON_CAMERA_ID[] = "cameraId";
    constexpr char COMMON_CAMERA_STATE[] = "cameraState";
    constexpr char COMMON_IS_SYSTEM_CAMERA[] = "isSystemCamera";
}
enum CameraType {
    SYSTEM = 0,
    OTHER
};

enum CameraStatus {
    CAMERA_OPEN = 0,
    CAMERA_CLOSE
};

CameraStrategy::CameraStrategy()
{
    DP_DEBUG_LOG("entered.");
}

CameraStrategy::~CameraStrategy()
{
    DP_DEBUG_LOG("entered.");
}

void CameraStrategy::handleEvent(const EventFwk::CommonEventData& data)
{
    auto want = data.GetWant();
    std::string cameraId = want.GetStringParam(COMMON_CAMERA_ID);
    int32_t state = want.GetIntParam(COMMON_CAMERA_STATE, CameraStatus::CAMERA_CLOSE);
    int32_t cameraType = want.GetIntParam(COMMON_IS_SYSTEM_CAMERA, CameraType::SYSTEM);
    bool isSystemCamera = cameraType == CameraType::SYSTEM;
    CameraSessionStatus cameraSessionStatus;
    if (state == CameraStatus::CAMERA_OPEN) {
        numActiveSessions_++;
        cameraSessionStatus = isSystemCamera ?
            CameraSessionStatus::SYSTEM_CAMERA_OPEN : CameraSessionStatus::NORMAL_CAMERA_OPEN;
    } else if (state == CameraStatus::CAMERA_CLOSE) {
        numActiveSessions_--;
        cameraSessionStatus = isSystemCamera ?
            CameraSessionStatus::SYSTEM_CAMERA_CLOSED : CameraSessionStatus::NORMAL_CAMERA_CLOSED;
    } else {
        return;
    }
    DP_INFO_LOG("DPS_EVENT: CameraStatusChanged state: %{public}d, cameraId: %{public}s, numActive: %{public}d",
        cameraSessionStatus, cameraId.c_str(), numActiveSessions_.load());
    EventsInfo::GetInstance().SetCameraState(cameraSessionStatus);
    EventsMonitor::GetInstance().NotifyCameraSessionStatus(cameraSessionStatus);
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS