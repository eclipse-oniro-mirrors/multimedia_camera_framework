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

#include "control_center_session_taihe.h"
#include "camera_log.h"
#include "camera_manager.h"
#include "napi/native_common.h"
#include <cstddef>
#include <memory>
#include <cstdint>
#include <vector>
#include <camera_utils_taihe.h>

namespace Ani {
namespace Camera {
using namespace taihe;
using namespace ohos::multimedia::camera;

uint32_t ControlCenterSessionImpl::controlCenterSessionTaskId_ = CAMERA_CONTROL_CENTER_TASKID;

array<double> ControlCenterSessionImpl::GetSupportedVirtualApertures()
{
    CHECK_RETURN_RET_ELOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        {},
        "SystemApi GetSupportedVirtualApertures is called!");
    MEDIA_DEBUG_LOG("ControlCenterSessionImpl::GetSupportedVirtualApertures is called");
    CHECK_RETURN_RET_ELOG(
        controlCenterSession_ == nullptr, {}, "GetSupportedVirtualApertures controlCenterSession is null");
    std::vector<float> virtualApertures = {};
    int32_t ret = controlCenterSession_->GetSupportedVirtualApertures(virtualApertures);
    if (ret != 0) {
        MEDIA_DEBUG_LOG("ControlCenterSessionImpl::GetVirtualAperture get failed");
        return {};
    }
    std::vector<double> doubleVec(virtualApertures.begin(), virtualApertures.end());
    return array<double>(doubleVec);
}

double ControlCenterSessionImpl::GetVirtualAperture()
{
    CHECK_RETURN_RET_ELOG(
        !OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(), 0.0, "SystemApi GetVirtualAperture is called!");
    MEDIA_DEBUG_LOG("ControlCenterSessionImpl::GetVirtualAperture is called");
    CHECK_RETURN_RET_ELOG(controlCenterSession_ == nullptr, 0.0, "GetVirtualAperture controlCenterSession is null");
    float virtualAperture = -1.0;
    int32_t ret = controlCenterSession_->GetVirtualAperture(virtualAperture);
    if (ret != 0) {
        MEDIA_DEBUG_LOG("ControlCenterSessionImpl::GetVirtualAperture get failed");
        return 0.0;
    }
    return static_cast<double>(virtualAperture);
}

void ControlCenterSessionImpl::SetVirtualAperture(double aperture)
{
    CHECK_RETURN_ELOG(
        !OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(), "SystemApi SetVirtualAperture is called!");
    MEDIA_DEBUG_LOG("ControlCenterSessionImpl::SetVirtualAperture is called");
    CHECK_RETURN_ELOG(controlCenterSession_ == nullptr, "SetVirtualAperture controlCenterSession is null");
    int32_t ret = controlCenterSession_->SetVirtualAperture(aperture);
    if (ret != 0) {
        MEDIA_DEBUG_LOG("ControlCenterSessionImpl::SetVirtualAperture set failed");
    }
}

array<PhysicalAperture> ControlCenterSessionImpl::GetSupportedPhysicalApertures()
{
    CHECK_RETURN_RET_ELOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        {},
        "SystemApi GetSupportedPhysicalApertures is called!");
    MEDIA_DEBUG_LOG("ControlCenterSessionImpl::GetSupportedPhysicalApertures is called");
    CHECK_RETURN_RET_ELOG(
        controlCenterSession_ == nullptr, {}, "GetSupportedPhysicalApertures controlCenterSession is null");
    std::vector<std::vector<float>> physicalApertures = {};
    int32_t ret = controlCenterSession_->GetSupportedPhysicalApertures(physicalApertures);
    if (ret != 0) {
        return {};
    }
    return CameraUtilsTaihe::ToTaiheArrayPhysicalAperture(physicalApertures);
}

double ControlCenterSessionImpl::GetPhysicalAperture()
{
    CHECK_RETURN_RET_ELOG(
        !OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(), 0.0, "SystemApi GetPhysicalAperture is called!");
    MEDIA_DEBUG_LOG("ControlCenterSessionImpl::GetPhysicalAperture is called");
    CHECK_RETURN_RET_ELOG(controlCenterSession_ == nullptr, 0.0, "GetPhysicalAperture controlCenterSession is null");
    float physicalAperture = 0.0;
    int32_t ret = controlCenterSession_->GetPhysicalAperture(physicalAperture);
    if (ret != 0) {
        MEDIA_DEBUG_LOG("ControlCenterSessionImpl::GetPhysicalAperture get failed");
        return 0.0;
    }
    return static_cast<double>(physicalAperture);
}

void ControlCenterSessionImpl::SetPhysicalAperture(double aperture)
{
    CHECK_RETURN_ELOG(
        !OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(), "SystemApi SetPhysicalAperture is called!");
    MEDIA_DEBUG_LOG("ControlCenterSessionImpl::SetPhysicalAperture is called");
    CHECK_RETURN_ELOG(controlCenterSession_ == nullptr, "SetPhysicalAperture controlCenterSession is null");
    int32_t ret = controlCenterSession_->SetPhysicalAperture(static_cast<float>(aperture));
    if (ret != 0) {
        MEDIA_DEBUG_LOG("ControlCenterSessionImpl::SetPhysicalAperture set failed");
    }
}

array<BeautyType> ControlCenterSessionImpl::GetSupportedBeautyTypes()
{
    CHECK_RETURN_RET_ELOG(
        !OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(), {}, "SystemApi GetSupportedBeautyTypes is called!");
    MEDIA_DEBUG_LOG("ControlCenterSessionImpl::GetSupportedBeautyTypes is called");
    CHECK_RETURN_RET_ELOG(controlCenterSession_ == nullptr, {}, "GetSupportedBeautyTypes controlCenterSession is null");
    std::vector<int32_t> beautyTypes = {};
    beautyTypes = controlCenterSession_->GetSupportedBeautyTypes();
    std::vector<OHOS::CameraStandard::BeautyType> res = {};
    for (int i = 0; i < beautyTypes.size(); i++) {
        res.push_back(static_cast<OHOS::CameraStandard::BeautyType>(static_cast<int>(beautyTypes[i])));
    }
    return CameraUtilsTaihe::ToTaiheArrayEnum<BeautyType, OHOS::CameraStandard::BeautyType>(res);
}

array<int32_t> ControlCenterSessionImpl::GetSupportedBeautyRange(BeautyType type)
{
    CHECK_RETURN_RET_ELOG(
        !OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(), {}, "SystemApi GetSupportedBeautyRange is called!");
    MEDIA_DEBUG_LOG("ControlCenterSessionImpl::GetSupportedBeautyRange is called");
    CHECK_RETURN_RET_ELOG(controlCenterSession_ == nullptr, {}, "GetSupportedBeautyRange controlCenterSession is null");
    std::vector<int32_t> beautyRanges;
    beautyRanges =
        controlCenterSession_->GetSupportedBeautyRange(static_cast<OHOS::CameraStandard::BeautyType>(type.get_value()));
    return array<int32_t>(beautyRanges);
}

int32_t ControlCenterSessionImpl::GetBeauty(BeautyType type)
{
    CHECK_RETURN_RET_ELOG(
        !OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(), 0, "SystemApi GetBeauty is called!");
    MEDIA_DEBUG_LOG("ControlCenterSessionImpl::GetBeauty is called");
    CHECK_RETURN_RET_ELOG(controlCenterSession_ == nullptr, 0, "GetBeauty controlCenterSession is null");
    int32_t result = controlCenterSession_->GetBeauty(static_cast<OHOS::CameraStandard::BeautyType>(type.get_value()));
    return result;
}

void ControlCenterSessionImpl::SetBeauty(BeautyType type, int32_t value)
{
    CHECK_RETURN_ELOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(), "SystemApi SetBeauty is called!");
    MEDIA_DEBUG_LOG("ControlCenterSessionImpl::SetBeauty is called");
    CHECK_RETURN_ELOG(controlCenterSession_ == nullptr, "SetBeauty controlCenterSession is null");
    controlCenterSession_->SetBeauty(static_cast<OHOS::CameraStandard::BeautyType>(type.get_value()), value);
}

array<PortraitThemeType> ControlCenterSessionImpl::GetSupportedPortraitThemeTypes()
{
    CHECK_RETURN_RET_ELOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        {},
        "SystemApi GetSupportedPortraitThemeTypes is called!");
    MEDIA_DEBUG_LOG("ControlCenterSessionImpl::GetSupportedPortraitThemeTypes is called");
    CHECK_RETURN_RET_ELOG(
        controlCenterSession_ == nullptr, {}, "GetSupportedPortraitThemeTypes controlCenterSession is null");
    std::vector<OHOS::CameraStandard::PortraitThemeType> types;
    int32_t ret = controlCenterSession_->GetSupportedPortraitThemeTypes(types);
    if (ret == 0 && types.size() > 0) {
        return CameraUtilsTaihe::ToTaiheArrayEnum<PortraitThemeType, OHOS::CameraStandard::PortraitThemeType>((types));
    }
    MEDIA_DEBUG_LOG("ControlCenterSessionImpl::GetSupportedPortraitThemeTypes get failed");
    return {};
}

bool ControlCenterSessionImpl::IsPortraitThemeSupported()
{
    CHECK_RETURN_RET_ELOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        false,
        "SystemApi IsPortraitThemeSupported is called!");
    MEDIA_DEBUG_LOG("ControlCenterSessionImpl::IsPortraitThemeSupported is called");
    CHECK_RETURN_RET_ELOG(controlCenterSession_ == nullptr, false, "SetPortraitThemeType controlCenterSession is null");
    bool flag = false;
    int32_t ret = controlCenterSession_->IsPortraitThemeSupported(flag);
    if (ret == 0) {
        return flag;
    } else {
        MEDIA_DEBUG_LOG("ControlCenterSessionImpl::IsPortraitThemeSupported get failed");
        return false;
    }
}

void ControlCenterSessionImpl::SetPortraitThemeType(PortraitThemeType type)
{
    CHECK_RETURN_ELOG(
        !OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(), "SystemApi SetPortraitThemeType is called!");
    MEDIA_DEBUG_LOG("ControlCenterSessionImpl::SetPortraitThemeType is called");
    CHECK_RETURN_ELOG(controlCenterSession_ == nullptr, "SetPortraitThemeType controlCenterSession is null");
    int32_t ret = controlCenterSession_->SetPortraitThemeType(
        static_cast<OHOS::CameraStandard::PortraitThemeType>(type.get_value()));
    if (ret != 0) {
        MEDIA_DEBUG_LOG("ControlCenterSessionImpl::SetPortraitThemeType set failed");
    }
}

bool ControlCenterSessionImpl::GetAutoFramingStatus()
{
    CHECK_RETURN_RET_ELOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        false,
        "SystemApi GetAutoFramingStatus is called!");
    MEDIA_DEBUG_LOG("ControlCenterSessionImpl::GetAutoFramingStatus is called");
    CHECK_RETURN_RET_ELOG(controlCenterSession_ == nullptr,
        false,
        "GetAutoFramingStatus controlCenterSession is null!");
    bool status = false;
    int32_t ret = controlCenterSession_->GetAutoFramingStatus(status);
    if (ret == 0) {
        return status;
    } else {
        MEDIA_DEBUG_LOG("ControlCenterSessionImpl::GetAutoFramingStatus failed");
        return false;
    }
}

void ControlCenterSessionImpl::EnableAutoFraming(bool enable)
{
    CHECK_RETURN_ELOG(
        !OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(), "SystemApi EnableAutoFraming is called!");
    MEDIA_DEBUG_LOG("ControlCenterSessionImpl::EnableAutoFraming is called");
    CHECK_RETURN_ELOG(controlCenterSession_ == nullptr, "EnableAutoFraming controlCenterSession is null");
    int32_t ret = controlCenterSession_->EnableAutoFraming(enable);
    if (ret != 0) {
        MEDIA_DEBUG_LOG("ControlCenterSessionImpl::EnableAutoFraming set failed");
    }
}

bool ControlCenterSessionImpl::IsAutoFramingSupported()
{
    CHECK_RETURN_RET_ELOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        false,
        "SystemApi IsAutoFramingSupported is called!");
    MEDIA_DEBUG_LOG("ControlCenterSessionImpl::IsAutoFramingSupported is called");
    CHECK_RETURN_RET_ELOG(controlCenterSession_ == nullptr,
        false,
        "IsAutoFramingSupported controlCenterSession is null!");
    bool support = false;
    int32_t ret = controlCenterSession_->IsAutoFramingSupported(support);
    if (ret != 0) {
        MEDIA_DEBUG_LOG("ControlCenterSessionImpl::IsAutoFramingSupported get failed");
        return false;
    }
    return support;
}

void ControlCenterSessionImpl::ReleaseSync()
{
    MEDIA_DEBUG_LOG("ReleaseSync is called");
    std::unique_ptr<ControlCenterSessionTaiheAsyncContext> asyncContext =
        std::make_unique<ControlCenterSessionTaiheAsyncContext>(
            "SessionImpl::ReleaseSync", CameraUtilsTaihe::IncrementAndGet(controlCenterSessionTaskId_));
    asyncContext->queueTask =
        CameraTaiheWorkerQueueKeeper::GetInstance()->AcquireWorkerQueueTask("ControlCenterSessionImpl::ReleaseSync");
    asyncContext->objectInfo = this;
    CAMERA_START_ASYNC_TRACE(asyncContext->funcName, asyncContext->taskId);
    CameraTaiheWorkerQueueKeeper::GetInstance()->ConsumeWorkerQueueTask(asyncContext->queueTask, [&asyncContext]() {
        CHECK_RETURN_ELOG(asyncContext->objectInfo == nullptr, "captureSession_ is nullptr");
        asyncContext->errorCode = asyncContext->objectInfo->controlCenterSession_->Release();
        CameraUtilsTaihe::CheckError(asyncContext->errorCode);
    });
    CAMERA_FINISH_ASYNC_TRACE(asyncContext->funcName, asyncContext->taskId);
}

}  // namespace Camera
}  // namespace Ani