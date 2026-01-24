/*
 * Copyright (c) 2026-2026 Huawei Device Co., Ltd.
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

#include "logic_camera_utils.h"

#include "camera_log.h"
#include "camera_util.h"
#include "camera_manager.h"
#include "camera_metadata_operator.h"

namespace OHOS {
namespace CameraStandard {
namespace LogicCameraUtils {
// LCOV_EXCL_START
int32_t GetFoldWithDirectionOrientationMap(common_metadata_header_t* metadata,
    std::unordered_map<uint32_t, std::vector<uint32_t>>& foldWithDirectionOrientationMap)
{
    CHECK_RETURN_RET_ELOG(
        metadata == nullptr, CAMERA_INVALID_ARG, "GetFoldWithDirectionOrientationMap metadata is nullptr");
    foldWithDirectionOrientationMap = {};
    camera_metadata_item_t item;
    int32_t ret = OHOS::Camera::FindCameraMetadataItem(metadata,
        OHOS_FOLD_STATE_AND_NATURAL_DIRECTION_SENSOR_ORIENTATION_MAP, &item);
    CHECK_RETURN_RET_ELOG(ret != CAM_META_SUCCESS, CAMERA_INVALID_STATE,
        "GetFoldWithDirectionOrientationMap FindCameraMetadataItem Error");
    uint32_t count = item.count;
    CHECK_RETURN_RET_ELOG(count % STEP_NINE, CAMERA_INVALID_STATE,
        "GetFoldWithDirectionOrientationMap FindCameraMetadataItem Count 9 Error");
    uint32_t unitLength = count / STEP_NINE;

    for (uint32_t index = 0; index < unitLength; index++) {
        uint32_t innerFoldState = static_cast<uint32_t>(item.data.i32[index * STEP_NINE]);
        std::vector<uint32_t> orientationWithNaturalDirection = {};
        for (uint32_t i = 1; i <= STEP_FOUR * STEP_TWO; i++) {
            orientationWithNaturalDirection.emplace_back(static_cast<uint32_t>(item.data.i32[index * STEP_NINE + i]));
        }
        MEDIA_DEBUG_LOG("GetFoldWithDirectionOrientationMap, foldstate: %{public}d, map: %{public}s", innerFoldState,
            Container2String(orientationWithNaturalDirection.begin(), orientationWithNaturalDirection.end()).c_str());
        foldWithDirectionOrientationMap[innerFoldState] = orientationWithNaturalDirection;
    }
    return CAMERA_OK;
}
// LCOV_EXCL_STOP

int32_t GetPhysicalOrientationByFoldAndDirection(const uint32_t foldStatus, uint32_t& orientation,
    const std::unordered_map<uint32_t, std::vector<uint32_t>>& foldWithDirectionOrientationMap)
{
    CHECK_RETURN_RET_DLOG(foldWithDirectionOrientationMap.empty(), CAMERA_INVALID_STATE,
        "GetPhysicalOrientationByFoldAndDirection foldWithDirectionOrientationMap is empty");
    auto cameraProxy = CameraManager::GetInstance()->GetServiceProxy();
    CHECK_RETURN_RET_ELOG(cameraProxy == nullptr, CAMERA_INVALID_STATE,
        "GetPhysicalOrientationByFoldAndDirection Failed to get cameraProxy");
    int32_t naturalDirection = 0;

    auto retCode = cameraProxy->GetAppNaturalDirection(naturalDirection);
    CHECK_RETURN_RET_DLOG(retCode != CAMERA_OK, retCode,
        "GetPhysicalOrientationByFoldAndDirection GetAppNaturalDirection Failed");
    MEDIA_DEBUG_LOG("GetPhysicalOrientationByFoldAndDirection foldStatus: %{public}d, naturalDirection: %{public}d",
        foldStatus, naturalDirection);
    auto item = foldWithDirectionOrientationMap.find(foldStatus);
    if (item != foldWithDirectionOrientationMap.end()) {
        std::vector<uint32_t> orientationWithNaturalDirection = item->second;
        CHECK_RETURN_RET_ELOG(orientationWithNaturalDirection.size() != STEP_FOUR * STEP_TWO, CAMERA_INVALID_STATE,
            "GetPhysicalOrientationByFoldAndDirection orientationWithNaturalDirection size error");
        for (uint32_t index = 0; index < STEP_FOUR; index++) {
            uint32_t innerNaturalDirection = orientationWithNaturalDirection[index * STEP_TWO];
            CHECK_CONTINUE(innerNaturalDirection != naturalDirection);
            orientation = orientationWithNaturalDirection[index * STEP_TWO + STEP_ONE];
            return CAMERA_OK;
        }
    }
    MEDIA_ERR_LOG("LogicCameraUtils::GetPhysicalOrientationByFoldAndDirection failed");
    return CAMERA_UNKNOWN_ERROR;
}

} // namespace LogicCameraUtils
} // namespace CameraStandard
} // namespace OHOS
