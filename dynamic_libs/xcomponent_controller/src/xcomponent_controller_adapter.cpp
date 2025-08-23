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

#include "xcomponent_controller_adapter.h"
#include "xcomponent_controller.h"
#include "camera_log.h"

namespace OHOS {
namespace CameraStandard {
// LCOV_EXCL_START
XComponentControllerAdapter::XComponentControllerAdapter()
{
    MEDIA_DEBUG_LOG("XComponentControllerAdapter ctor");
}

int32_t XComponentControllerAdapter::GetRenderFitBySurfaceId(
    const std::string& surfaceId, int32_t& renderFitNumber, bool& isRenderFitNewVersionEnabled)
{
    MEDIA_INFO_LOG("XComponentControllerAdapter::GetRenderFitBySurfaceId called");
    int32_t ret = OHOS::Ace::XComponentController::GetRenderFitBySurfaceId(
        surfaceId, renderFitNumber, isRenderFitNewVersionEnabled);
    CHECK_PRINT_ELOG(ret != 0, "GetRenderFitBySurfaceId ret: %{public}d", ret);
    return ret;
}

int32_t XComponentControllerAdapter::SetRenderFitBySurfaceId(
    const std::string& surfaceId, int32_t renderFitNumber, bool isRenderFitNewVersionEnabled)
{
    MEDIA_INFO_LOG("XComponentControllerAdapter::SetRenderFitBySurfaceId called");
    int32_t ret = OHOS::Ace::XComponentController::SetRenderFitBySurfaceId(
        surfaceId, renderFitNumber, isRenderFitNewVersionEnabled);
    CHECK_PRINT_ELOG(ret != 0, "SetRenderFitBySurfaceId ret: %{public}d", ret);
    return ret;
}

// LCOV_EXCL_STOP
extern "C" XComponentControllerIntf *createXComponentControllerIntf()
{
    return new XComponentControllerAdapter();
}
}  // namespace AVSession
}  // namespace OHOS