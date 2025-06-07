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
#include <dlfcn.h>
#include <unistd.h>
#include <regex>
#include "ipc_skeleton.h"
#include "bundle_mgr_interface.h"
#include "system_ability_definition.h"
#include "camera_fwk_metadata_utils.h"
#include "camera_log.h"
#include "rotate_plugin/camera_rotate_plugin.h"
#include "camera_util.h"
#include "surface.h"
#include "hcapture_session.h"
#include "parameters.h"

namespace OHOS {
namespace CameraStandard {
#if (defined(__aarch64__) || defined(__x86_64__))
const std::string CAMERA_PLUGIN_SO_PATH = "/system/lib64/libcompatible_policy_camera.z.so";
#else
const std::string CAMERA_PLUGIN_SO_PATH = "/system/lib/libcompatible_policy_camera.z.so";
#endif
using  UpdateParameterFunc = bool(*)(ParameterMap&, ParameterMap&);
bool CameraRotatePlugin::initResult = false;
sptr<CameraRotatePlugin> CameraRotatePlugin::cameraRotatePlugin_;
std::mutex CameraRotatePlugin::instanceMutex_;
sptr<CameraRotatePlugin> &CameraRotatePlugin::GetInstance()
{
    if (cameraRotatePlugin_ == nullptr) {
        std::unique_lock<std::mutex> lock(instanceMutex_);
        if (cameraRotatePlugin_ == nullptr) {
            MEDIA_INFO_LOG("Initializing CameraRotatePlugin instance");
            cameraRotatePlugin_ = new CameraRotatePlugin();
            initResult = cameraRotatePlugin_->Init();
        }
    }
    return CameraRotatePlugin::cameraRotatePlugin_;
}

CameraRotatePlugin::CameraRotatePlugin()
{
    MEDIA_INFO_LOG("CameraRotatePlugin construct");
}

CameraRotatePlugin::~CameraRotatePlugin()
{
    if (handle_) {
        dlclose(handle_);
        handle_ = nullptr;
    }
}


void CameraRotatePlugin::SetCaptureSession(const std::string& bundleName, wptr<HCaptureSession> hcaptureSession)
{
    captureSessionMap_.EnsureInsert(bundleName, hcaptureSession);
}

bool CameraRotatePlugin::HookCameraAbility(const std::string& cameraId,
    std::shared_ptr<OHOS::Camera::CameraMetadata>& inability)
{
    if (inability == nullptr) {
        return false;
    }
    ParameterMap param;
    int uid = IPCSkeleton::GetCallingUid();
    InitParam(GetClientBundle(uid), inability, cameraId, param);

    camera_metadata_item_t item;
    int32_t ret = OHOS::Camera::FindCameraMetadataItem(inability->get(), OHOS_ABILITY_CAMERA_POSITION, &item);
    if (ret == CAM_META_SUCCESS) {
        param[PLUGIN_CAMERA_POSITION] = to_string(item.data.u8[0]);
    } else {
        return false;
    }
    ret = OHOS::Camera::FindCameraMetadataItem(inability->get(), OHOS_SENSOR_ORIENTATION, &item);
    if (ret == CAM_META_SUCCESS) {
        param[PLUGIN_SENSOR_ORIENTATION] = to_string(item.data.i32[0]);
    } else {
        return false;
    }
    uint8_t cameraPosition = 0;
    int32_t sensorOrientation = 0;
    if (GetCameraAbility(param, cameraPosition, sensorOrientation)) {
        std::shared_ptr<OHOS::Camera::CameraMetadata> outputCapability =
            CameraFwkMetadataUtils::CopyMetadata(inability);
        outputCapability->updateEntry(OHOS_ABILITY_CAMERA_POSITION, &cameraPosition, 1);
        outputCapability->updateEntry(OHOS_SENSOR_ORIENTATION, &sensorOrientation, 1);
        inability = outputCapability;
        return true;
    }
    return false;
}

bool CameraRotatePlugin::HookOpenDeviceForRotate(const std::string& bundleName,
    std::shared_ptr<OHOS::Camera::CameraMetadata> inputCapability, const std::string& cameraId)
{
    ParameterMap param;
    InitParam(bundleName, inputCapability, cameraId, param);
    return SubscribeUpdateSettingCallback(param);
}

bool CameraRotatePlugin::HookCloseDeviceForRotate(const std::string& bundleName,
    std::shared_ptr<OHOS::Camera::CameraMetadata> inputCapability, const std::string& cameraId)
{
    ParameterMap param;
    InitParam(bundleName, inputCapability, cameraId, param);
    return UnSubscribeUpdateSettingCallback(param);
}

bool CameraRotatePlugin::HookCreatePreviewFormat(const std::string& bundleName, int32_t& format)
{
    ParameterMap param = {
        {PLUGIN_BUNDLE_NAME, bundleName},
        {PLUGIN_PREVIEW_FORMAT, to_string(format)}
    };
    return CreatePreviewOutput(param, format);
}

bool CameraRotatePlugin::HookCreateVideoOutput(ParameterMap basicInfoMap, const sptr<OHOS::IBufferProducer>& producer)
{
    if (producer == nullptr) {
        return false;
    }
    std::string surfaceAppFwkType = "";
    uint32_t transform = 0;
    if (CreateVideoOutput(basicInfoMap, surfaceAppFwkType, transform)) {
        producer->SetTransform(static_cast<OHOS::GraphicTransformType>(transform));
        producer->SetSurfaceAppFrameworkType(surfaceAppFwkType);
        return true;
    }
    return false;
}

bool CameraRotatePlugin::HookPreviewStreamStart(ParameterMap basicInfoMap,
    const sptr<OHOS::IBufferProducer>& producer, int32_t& rotateAngle)
{
    if (producer == nullptr) {
        return false;
    }
    MEDIA_DEBUG_LOG("CameraRotatePlugin::HookPreviewStreamStart enter");
    int32_t frameGravity = -1;
    int32_t fixedRotation = -1;
    if (PreviewStreamStart(basicInfoMap, frameGravity, fixedRotation, rotateAngle)) {
        MEDIA_DEBUG_LOG("CameraRotatePlugin::HookPreviewStreamStart %{public}d  %{public}d",
            frameGravity, fixedRotation);
        producer->SetFrameGravity(frameGravity);
        producer->SetFixedRotation(fixedRotation);
        return true;
    }
    return false;
}

bool CameraRotatePlugin::HookPreviewTransform(ParameterMap basicInfoMap,
    const sptr<OHOS::IBufferProducer>& producer,
    int32_t& sensorOrientation, int32_t& cameraPosition)
{
    if (producer == nullptr) {
        return false;
    }
    int32_t frameGravity = -1;
    int32_t fixedRotation = -1;
    if (PreviewTransform(basicInfoMap, frameGravity, fixedRotation, sensorOrientation, cameraPosition)) {
        producer->SetFrameGravity(frameGravity);
        producer->SetFixedRotation(fixedRotation);
        return true;
    }
    return false;
}

bool CameraRotatePlugin::HookVideoStreamStart(ParameterMap basicInfoMap,
    const sptr<OHOS::IBufferProducer>& producer, bool& mirror)
{
    if (producer == nullptr) {
        return false;
    }

    std::string surfaceAppFwkType = "";
    uint32_t transform = 0;
    if (VideoStreamStart(basicInfoMap, surfaceAppFwkType, transform, mirror)) {
        producer->SetTransform(static_cast<OHOS::GraphicTransformType>(transform));
        producer->SetSurfaceAppFrameworkType(surfaceAppFwkType);
        return true;
    }
    return false;
}

bool CameraRotatePlugin::HookCaptureStreamStart(ParameterMap basicInfoMap, int32_t& jpegOrientation, bool& mirror)
{
    return CaptureStreamStart(basicInfoMap, jpegOrientation, mirror);
}

void* CameraRotatePlugin::GetFunction(const std::string& functionName)
{
    CHECK_DEBUG_RETURN_RET_LOG(
        handle_ == nullptr, nullptr, "CameraRotatePlugin::GetFunction fail not loaded");
    void* funcInstance = nullptr;
    if (functionMap_.Find(functionName, funcInstance)) {
        return funcInstance;
    }
    void* handleFunc = dlsym(handle_, functionName.c_str());
    CHECK_DEBUG_RETURN_RET_LOG(
        handleFunc == nullptr, nullptr, "CameraRotatePlugin::GetFunction fail function:%{public}s not find",
        functionName.c_str());
    MEDIA_INFO_LOG("CameraRotatePlugin::GetFunction %{public}s success", functionName.c_str());
    functionMap_.EnsureInsert(functionName, handleFunc);
    return handleFunc;
}

bool CameraRotatePlugin::GetParameterResult(ParameterMap basicInfoMap, const std::string& functionName,
    ParameterMap& parameterMap)
{
    UpdateParameterFunc updateParameterFunc = (UpdateParameterFunc)GetFunction(functionName);
    CHECK_DEBUG_RETURN_RET_LOG(updateParameterFunc == nullptr, false,
        "function %{public}s is failed", functionName.c_str());
    bool result = updateParameterFunc(basicInfoMap, parameterMap);
    CHECK_DEBUG_RETURN_RET_LOG(!result, false, "function %{public}s is failed", functionName.c_str());
    return true;
}

void CameraRotatePlugin::InitParam(const std::string& bundleName,
    std::shared_ptr<OHOS::Camera::CameraMetadata> inputCapability, const std::string& cameraId, ParameterMap& param)
{
    if (inputCapability == nullptr) {
        return;
    }
    camera_metadata_item_t item;
    int32_t ret = OHOS::Camera::FindCameraMetadataItem(inputCapability->get(),
        OHOS_ABILITY_CAMERA_CONNECTION_TYPE, &item);
    int32_t connectionType = 0;
    if (ret == CAM_META_SUCCESS) {
        connectionType = static_cast<int32_t>(item.data.u8[0]);
    }
    param[PLUGIN_BUNDLE_NAME] = bundleName;
    param[PLUGIN_CAMERA_ID] = cameraId;
    param[PLUGIN_CAMERA_CONNECTION_TYPE] = std::to_string(connectionType);
}

bool CameraRotatePlugin::Init()
{
    if (handle_) {
        ParameterMap updateParameter;
        return GetParameterResult(updateParameter, "Init", updateParameter);
    }
    if (system::GetParameter("const.camera.compatible_policy_camera.enable", "false") != "true" ||
        access(CAMERA_PLUGIN_SO_PATH.c_str(), R_OK) != 0) {
        MEDIA_ERR_LOG("so file not exist.");
        return false;
    }
    handle_ = ::dlopen(CAMERA_PLUGIN_SO_PATH.c_str(), RTLD_NOW);
    if (!handle_) {
        MEDIA_ERR_LOG("dlopen failed check so file exists");
        return false;
    }
    ParameterMap updateParameter;
    bool result = GetParameterResult(updateParameter, "Init", updateParameter);
    return result;
}

bool CameraRotatePlugin::GetCameraAbility(ParameterMap basicInfoMap,
    uint8_t& cameraPosition, int32_t& sensorOrientation)
{
    ParameterMap updateParameter;
    bool result = GetParameterResult(basicInfoMap, "GetCameraAbility", updateParameter);
    CHECK_ERROR_RETURN_RET_LOG((updateParameter.size() < 1 || !result), false, "GetCameraAbility is failed");
    result = (updateParameter.find(PLUGIN_CAMERA_POSITION) != updateParameter.end()) &&
        (updateParameter.find(PLUGIN_SENSOR_ORIENTATION) != updateParameter.end());
    CHECK_ERROR_RETURN_RET_LOG(!result, false, "updateParameter result not include needed parameter");
    result = isIntegerRegex(updateParameter[PLUGIN_CAMERA_POSITION]) &&
        isIntegerRegex(updateParameter[PLUGIN_SENSOR_ORIENTATION]);
    CHECK_ERROR_RETURN_RET_LOG(!result, false, "updateParameter result not valid number");
    cameraPosition = std::stoi(updateParameter[PLUGIN_CAMERA_POSITION]);
    sensorOrientation = std::stoi(updateParameter[PLUGIN_SENSOR_ORIENTATION]);
    return result;
}

int32_t CameraRotatePlugin::OnParameterChange(ParameterMap ParameterMap)
{
    wptr<HCaptureSession> hcaptureSessionWptr;
    captureSessionMap_.Find(ParameterMap[PLUGIN_BUNDLE_NAME], hcaptureSessionWptr);
    sptr<HCaptureSession> hcaptureSessionSptr = hcaptureSessionWptr.promote();
    CHECK_ERROR_RETURN_RET_LOG((hcaptureSessionSptr == nullptr || ParameterMap.size() < 1), CAMERA_INVALID_ARG,
        "hcaptureSession is null");
    hcaptureSessionSptr->UpdateHookBasicInfo(ParameterMap);
    return 0;
}

using OpenCameraDeviceFunc = bool(*)(ParameterMap&, UpdateSettingsCallback, ParameterMap&);
bool CameraRotatePlugin::SubscribeUpdateSettingCallback(ParameterMap basicInfoMap)
{
    OpenCameraDeviceFunc openCameraDeviceFunc = (OpenCameraDeviceFunc)GetFunction("SubscribeUpdateSettingCallback");
    CHECK_ERROR_RETURN_RET_LOG(openCameraDeviceFunc == nullptr, false, "SubscribeUpdateSettingCallback is failed");
    // 定义接口
    UpdateSettingsCallback callback = std::bind(&CameraRotatePlugin::OnParameterChange, this, std::placeholders::_1);
    ParameterMap updateParameter;
    bool result = openCameraDeviceFunc(basicInfoMap, callback, updateParameter);
    CHECK_ERROR_RETURN_RET_LOG(!result, false, "SubscribeUpdateSettingCallback is failed");
    return true;
}

bool CameraRotatePlugin::UnSubscribeUpdateSettingCallback(ParameterMap basicInfoMap)
{
    ParameterMap updateParameter;
    bool result = GetParameterResult(basicInfoMap, "UnSubscribeUpdateSettingCallback", updateParameter);
    CHECK_ERROR_RETURN_RET_LOG(!result, false, "UnSubscribeUpdateSettingCallback is failed");
    captureSessionMap_.Erase(basicInfoMap[PLUGIN_BUNDLE_NAME]);
    return result;
}

bool CameraRotatePlugin::CreatePreviewOutput(ParameterMap basicInfoMap, int32_t& format)
{
    ParameterMap updateParameter;
    bool result = GetParameterResult(basicInfoMap, "CreatePreviewOutput", updateParameter);
    CHECK_ERROR_RETURN_RET_LOG((updateParameter.size() < 1 || !result), false, "CreatePreviewOutput is failed");
    result = updateParameter.find(PLUGIN_PREVIEW_FORMAT) != updateParameter.end() &&
        isIntegerRegex(updateParameter[PLUGIN_PREVIEW_FORMAT]);
    CHECK_ERROR_RETURN_RET_LOG(!result, false, "CreatePreviewOutput updateParameter result not valid number");
    format = std::stoi(updateParameter[PLUGIN_PREVIEW_FORMAT]);
    return true;
}

bool CameraRotatePlugin::PreviewStreamStart(ParameterMap basicInfoMap, int32_t& frameGravity,
    int32_t& fixedRotation, int32_t& rotateAngle)
{
    ParameterMap updateParameter;
    bool result = GetParameterResult(basicInfoMap, "PreviewStreamStart", updateParameter);
    CHECK_ERROR_RETURN_RET_LOG((updateParameter.size() < 1 || !result), false, "PreviewStreamStart is failed");
    result = updateParameter.find(PLUGIN_CAMERA_HAL_ROTATE_ANGLE) != updateParameter.end();
    CHECK_ERROR_RETURN_RET_LOG(!result, false, "PreviewStreamStart result not include needed parameter");
    CHECK_EXECUTE(updateParameter.find(PLUGIN_SURFACE_FRAME_GRAVITY) != updateParameter.end() &&
        isIntegerRegex(updateParameter[PLUGIN_SURFACE_FIXED_ROTATION]),
        frameGravity = std::stoi(updateParameter[PLUGIN_SURFACE_FRAME_GRAVITY]));
    CHECK_EXECUTE(updateParameter.find(PLUGIN_SURFACE_FIXED_ROTATION) != updateParameter.end() &&
        isIntegerRegex(updateParameter[PLUGIN_SURFACE_FIXED_ROTATION]),
        fixedRotation = std::stoi(updateParameter[PLUGIN_SURFACE_FIXED_ROTATION]));
    rotateAngle = std::stoi(updateParameter[PLUGIN_CAMERA_HAL_ROTATE_ANGLE]);
    return true;
}

bool CameraRotatePlugin::PreviewTransform(ParameterMap basicInfoMap, int32_t& frameGravity, int32_t& fixedRotation,
    int32_t& sensorOrientation, int32_t& cameraPosition)
{
    ParameterMap updateParameter;
    bool result = GetParameterResult(basicInfoMap, "PreviewTransform", updateParameter);
    CHECK_ERROR_RETURN_RET_LOG((updateParameter.size() < 1 || !result), false, "PreviewTransform is failed");
    result = (updateParameter.find(PLUGIN_SURFACE_FRAME_GRAVITY) != updateParameter.end()) &&
        (updateParameter.find(PLUGIN_SURFACE_FIXED_ROTATION) != updateParameter.end()) &&
        (updateParameter.find(PLUGIN_CAMERA_POSITION) != updateParameter.end()) &&
        (updateParameter.find(PLUGIN_SENSOR_ORIENTATION) != updateParameter.end());
    CHECK_ERROR_RETURN_RET_LOG(!result, false, "PreviewTransform result not include needed parameter");
    result = isIntegerRegex(updateParameter[PLUGIN_SURFACE_FRAME_GRAVITY]) &&
        isIntegerRegex(updateParameter[PLUGIN_SURFACE_FIXED_ROTATION]) &&
        isIntegerRegex(updateParameter[PLUGIN_CAMERA_POSITION]) &&
        isIntegerRegex(updateParameter[PLUGIN_SENSOR_ORIENTATION]);
    frameGravity = std::stoi(updateParameter[PLUGIN_SURFACE_FRAME_GRAVITY]);
    fixedRotation = std::stoi(updateParameter[PLUGIN_SURFACE_FIXED_ROTATION]);
    cameraPosition = std::stoi(updateParameter[PLUGIN_CAMERA_POSITION]);
    sensorOrientation = std::stoi(updateParameter[PLUGIN_SENSOR_ORIENTATION]);
    return true;
}

bool CameraRotatePlugin::CaptureStreamStart(ParameterMap basicInfoMap, int32_t& jpegOrientation, bool& mirror)
{
    ParameterMap updateParameter;
    basicInfoMap[PLUGIN_JPEG_ORIENTATION] = to_string(jpegOrientation);
    basicInfoMap[PLUGIN_CAPTURE_MIRROR] = to_string(mirror);
    bool result = GetParameterResult(basicInfoMap, "CaptureStreamStart", updateParameter);
    CHECK_ERROR_RETURN_RET_LOG((updateParameter.size() < 1 || !result), false, "CaptureStreamStart is failed");
    result = (updateParameter.find(PLUGIN_CAPTURE_MIRROR) != updateParameter.end()) &&
        (updateParameter.find(PLUGIN_JPEG_ORIENTATION) != updateParameter.end());
    CHECK_ERROR_RETURN_RET_LOG(!result, false, "CaptureStreamStart result not include needed parameter");
    result = isIntegerRegex(updateParameter[PLUGIN_JPEG_ORIENTATION]) &&
        isIntegerRegex(updateParameter[PLUGIN_CAPTURE_MIRROR]);
    CHECK_ERROR_RETURN_RET_LOG(!result, false, "CaptureStreamStart result not valid parameter");
    result = (std::stoi(updateParameter[PLUGIN_CAPTURE_MIRROR]) == 0 ||
        std::stoi(updateParameter[PLUGIN_CAPTURE_MIRROR]) == 1);
    CHECK_ERROR_RETURN_RET_LOG(!result, false, "CaptureStreamStart result not valid bool parameter");
    jpegOrientation = std::stoi(updateParameter[PLUGIN_JPEG_ORIENTATION]);
    mirror = std::stoi(updateParameter[PLUGIN_CAPTURE_MIRROR]);
    return true;
}

bool CameraRotatePlugin::CreateVideoOutput(ParameterMap basicInfoMap, std::string& surfaceAppFwkType,
    uint32_t& transform)
{
    ParameterMap updateParameter;
    basicInfoMap[PLUGIN_VIDEO_SURFACE_TRANSFORM] = to_string(transform);
    bool result = GetParameterResult(basicInfoMap, "CreateVideoOutput", updateParameter);
    CHECK_ERROR_RETURN_RET_LOG((updateParameter.size() < 1 || !result), false, "CreateVideoOutput is failed");
    result = (updateParameter.find(PLUGIN_SURFACE_APP_FWK_TYPE) != updateParameter.end()) &&
        (updateParameter.find(PLUGIN_VIDEO_SURFACE_TRANSFORM) != updateParameter.end());
    CHECK_ERROR_RETURN_RET_LOG(!result, false, "CreateVideoOutput result not include needed parameter");
    result = isIntegerRegex(updateParameter[PLUGIN_VIDEO_SURFACE_TRANSFORM]);
    CHECK_ERROR_RETURN_RET_LOG(!result, false, "CreateVideoOutput result not valid parameter");
    surfaceAppFwkType = updateParameter[PLUGIN_SURFACE_APP_FWK_TYPE];
    transform = std::stoi(updateParameter[PLUGIN_VIDEO_SURFACE_TRANSFORM]);
    return true;
}

bool CameraRotatePlugin::VideoStreamStart(ParameterMap basicInfoMap, std::string& surfaceAppFwkType,
    uint32_t& transform, bool& mirror)
{
    ParameterMap updateParameter;
    basicInfoMap[PLUGIN_VIDEO_SURFACE_TRANSFORM] = to_string(transform);
    bool result = GetParameterResult(basicInfoMap, "VideoStreamStart", updateParameter);
    CHECK_ERROR_RETURN_RET_LOG((updateParameter.size() < 1 || !result), false, "VideoStreamStart is failed");
    result = (updateParameter.find(PLUGIN_SURFACE_APP_FWK_TYPE) != updateParameter.end()) &&
        (updateParameter.find(PLUGIN_VIDEO_SURFACE_TRANSFORM) != updateParameter.end()) &&
        (updateParameter.find(PLUGIN_VIDEO_MIRROR) != updateParameter.end());
    CHECK_ERROR_RETURN_RET_LOG(!result, false, "VideoStreamStart result not include needed parameter");
    result = isIntegerRegex(updateParameter[PLUGIN_VIDEO_SURFACE_TRANSFORM]) &&
        isIntegerRegex(updateParameter[PLUGIN_VIDEO_MIRROR]);
    CHECK_ERROR_RETURN_RET_LOG(!result, false, "VideoStreamStart result not valid parameter");
    surfaceAppFwkType = updateParameter[PLUGIN_SURFACE_APP_FWK_TYPE];
    transform = std::stoi(updateParameter[PLUGIN_VIDEO_SURFACE_TRANSFORM]);
    mirror = std::stoi(updateParameter[PLUGIN_VIDEO_MIRROR]);
    return true;
}
}
}
