/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include <vector>

#include "accesstoken_kit.h"
#include "camera_device_service_proxy.h"
#include "camera_error_code.h"
#include "camera_log.h"
#include "camera_mute_service_callback_proxy.h"
#include "camera_service_client_unittest.h"
#include "capture_session.h"
#include "fold_service_callback_proxy.h"
#include "gtest/gtest.h"
#include "hcamera_service.h"
#include "input/camera_input.h"
#include "input/camera_manager.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "nativetoken_kit.h"
#include "system_ability_definition.h"
#include "test_token.h"
#include "token_setproc.h"
#include "torch_service_callback_proxy.h"

using namespace testing::ext;
using namespace OHOS::HDI::Camera::V1_0;
namespace OHOS {
namespace CameraStandard {

bool g_camInputOnError = false;
bool g_sessionclosed = false;
bool g_brightnessStatusChanged = false;
bool g_slowMotionStatusChanged = false;
bool g_isSupportedDeviceStatus = false;
std::shared_ptr<OHOS::Camera::CameraMetadata> g_metaResult = nullptr;
int32_t g_videoFd = -1;
int32_t g_previewFd = -1;
int32_t g_sketchFd = -1;
std::bitset<static_cast<int>(CAM_PHOTO_EVENTS::CAM_PHOTO_MAX_EVENT)> g_photoEvents;
std::bitset<static_cast<unsigned int>(CAM_PREVIEW_EVENTS::CAM_PREVIEW_MAX_EVENT)> g_previewEvents;
std::bitset<static_cast<unsigned int>(CAM_VIDEO_EVENTS::CAM_VIDEO_MAX_EVENT)> g_videoEvents;
std::bitset<static_cast<unsigned int>(CAM_MACRO_DETECT_EVENTS::CAM_MACRO_EVENT_MAX_EVENT)> g_macroEvents;
std::bitset<static_cast<unsigned int>(CAM_MOON_CAPTURE_BOOST_EVENTS::CAM_MOON_CAPTURE_BOOST_EVENT_MAX_EVENT)>
    g_moonCaptureBoostEvents;
std::list<int32_t> g_sketchStatus;
std::unordered_map<std::string, int> g_camStatusMap;
std::unordered_map<std::string, bool> g_camFlashMap;
TorchStatusInfo g_torchInfo;

void AppCallback::OnCameraStatusChanged(const CameraStatusInfo& cameraDeviceInfo) const
{
    const std::string cameraID = cameraDeviceInfo.cameraDevice->GetID();
    const CameraStatus cameraStatus = cameraDeviceInfo.cameraStatus;
    EXPECT_TRUE(true)<<"OnCameraStatusChanged:CameraId="<<cameraID<<",CameraStatus="<<cameraDeviceInfo.cameraStatus
        <<",bundleName="<<cameraDeviceInfo.bundleName<<endl;
    switch (cameraStatus) {
        case CAMERA_STATUS_UNAVAILABLE: {
            MEDIA_DEBUG_LOG(
                "AppCallback::OnCameraStatusChanged %{public}s: CAMERA_STATUS_UNAVAILABLE", cameraID.c_str());
            g_camStatusMap[cameraID] = CAMERA_STATUS_UNAVAILABLE;
            break;
        }
        case CAMERA_STATUS_AVAILABLE: {
            MEDIA_DEBUG_LOG(
                "AppCallback::OnCameraStatusChanged %{public}s: CAMERA_STATUS_AVAILABLE", cameraID.c_str());
            g_camStatusMap[cameraID] = CAMERA_STATUS_AVAILABLE;
            break;
        }
        default: {
            MEDIA_DEBUG_LOG("AppCallback::OnCameraStatusChanged %{public}s: unknown", cameraID.c_str());
            EXPECT_TRUE(false);
        }
    }
}

void AppCallback::OnFlashlightStatusChanged(const std::string& cameraID, const FlashStatus flashStatus) const
{
    MEDIA_DEBUG_LOG("AppCallback::OnFlashlightStatusChanged() is called!");
    switch (flashStatus) {
        case FLASH_STATUS_OFF: {
            MEDIA_DEBUG_LOG(
                "AppCallback::OnFlashlightStatusChanged %{public}s: FLASH_STATUS_OFF", cameraID.c_str());
            g_camFlashMap[cameraID] = false;
            break;
        }
        case FLASH_STATUS_ON: {
            MEDIA_DEBUG_LOG("AppCallback::OnFlashlightStatusChanged %{public}s: FLASH_STATUS_ON", cameraID.c_str());
            g_camFlashMap[cameraID] = true;
            break;
        }
        case FLASH_STATUS_UNAVAILABLE: {
            MEDIA_DEBUG_LOG(
                "AppCallback::OnFlashlightStatusChanged %{public}s: FLASH_STATUS_UNAVAILABLE", cameraID.c_str());
            g_camFlashMap.erase(cameraID);
            break;
        }
        default: {
            MEDIA_DEBUG_LOG("AppCallback::OnFlashlightStatusChanged %{public}s: unknown", cameraID.c_str());
            EXPECT_TRUE(false);
        }
    }
}

void AppCallback::OnTorchStatusChange(const TorchStatusInfo &torchStatusInfo) const
{
    MEDIA_DEBUG_LOG("TorchListener::OnTorchStatusChange called %{public}d %{public}d %{public}f",
        torchStatusInfo.isTorchAvailable, torchStatusInfo.isTorchActive, torchStatusInfo.torchLevel);
    g_torchInfo = torchStatusInfo;
}

void AppCallback::OnError(const int32_t errorType, const int32_t errorMsg) const
{
    MEDIA_DEBUG_LOG("AppCallback::OnError errorType: %{public}d, errorMsg: %{public}d", errorType, errorMsg);
    g_camInputOnError = true;
    if (errorType == CAMERA_DEVICE_PREEMPTED) {
        g_sessionclosed = true;
    }
}

void AppCallback::OnResult(const uint64_t timestamp, const std::shared_ptr<OHOS::Camera::CameraMetadata>& result) const
{
    MEDIA_INFO_LOG("CameraDeviceServiceCallback::OnResult() is called!");

    if (result != nullptr) {
        g_metaResult = result;
        common_metadata_header_t* data = result->get();
        std::vector<int32_t> fpsRange;
        camera_metadata_item_t entry;
        int ret = OHOS::Camera::FindCameraMetadataItem(data, OHOS_ABILITY_FPS_RANGES, &entry);
        MEDIA_INFO_LOG("CameraDeviceServiceCallback::FindCameraMetadataItem() %{public}d", ret);
        if (ret != 0) {
            MEDIA_INFO_LOG("demo test: get OHOS_ABILITY_FPS_RANGES error");
        }
        uint32_t count = entry.count;
        MEDIA_INFO_LOG("demo test: fpsRange count  %{public}d", count);
        for (uint32_t i = 0; i < count; i++) {
            fpsRange.push_back(*(entry.data.i32 + i));
        }
        for (auto it = fpsRange.begin(); it != fpsRange.end(); it++) {
            MEDIA_INFO_LOG("demo test: fpsRange %{public}d ", *it);
        }
    }
}

void AppCallback::OnCaptureStarted(const int32_t captureId) const
{
    MEDIA_DEBUG_LOG("AppCallback::OnCaptureStarted captureId: %{public}d", captureId);
    g_photoEvents[static_cast<int>(CAM_PHOTO_EVENTS::CAM_PHOTO_CAPTURE_START)] = 1;
}

void AppCallback::OnCaptureStarted(const int32_t captureId, uint32_t exposureTime) const
{
    MEDIA_DEBUG_LOG("AppCallback::OnCaptureStarted captureId: %{public}d", captureId);
    g_photoEvents[static_cast<int>(CAM_PHOTO_EVENTS::CAM_PHOTO_CAPTURE_START)] = 1;
}

void AppCallback::OnCaptureEnded(const int32_t captureId, const int32_t frameCount) const
{
    MEDIA_DEBUG_LOG("AppCallback::OnCaptureEnded captureId: %{public}d, frameCount: %{public}d",
                    captureId, frameCount);
    g_photoEvents[static_cast<int>(CAM_PHOTO_EVENTS::CAM_PHOTO_CAPTURE_END)] = 1;
}

void AppCallback::OnFrameShutter(const int32_t captureId, const uint64_t timestamp) const
{
    MEDIA_DEBUG_LOG(
        "AppCallback::OnFrameShutter captureId: %{public}d, timestamp: %{public}" PRIu64, captureId, timestamp);
    g_photoEvents[static_cast<int>(CAM_PHOTO_EVENTS::CAM_PHOTO_FRAME_SHUTTER)] = 1;
}

void AppCallback::OnFrameShutterEnd(const int32_t captureId, const uint64_t timestamp) const
{
    MEDIA_DEBUG_LOG(
        "AppCallback::OnFrameShutterEnd captureId: %{public}d, timestamp: %{public}" PRIu64, captureId, timestamp);
    g_photoEvents[static_cast<int>(CAM_PHOTO_EVENTS::CAM_PHOTO_FRAME_SHUTTER_END)] = 1;
}

void AppCallback::OnCaptureReady(const int32_t captureId, const uint64_t timestamp) const
{
    MEDIA_DEBUG_LOG(
        "AppCallback::OnCaptureReady captureId: %{public}d, timestamp: %{public}" PRIu64, captureId, timestamp);
    g_photoEvents[static_cast<int>(CAM_PHOTO_EVENTS::CAM_PHOTO_CAPTURE_READY)] = 1;
}

void AppCallback::OnEstimatedCaptureDuration(const int32_t duration) const
{
    MEDIA_DEBUG_LOG("AppCallback::OnEstimatedCaptureDuration duration: %{public}d", duration);
    g_photoEvents[static_cast<int>(CAM_PHOTO_EVENTS::CAM_PHOTO_ESTIMATED_CAPTURE_DURATION)] = 1;
}

void AppCallback::OnCaptureError(const int32_t captureId, const int32_t errorCode) const
{
    MEDIA_DEBUG_LOG(
        "AppCallback::OnCaptureError captureId: %{public}d, errorCode: %{public}d", captureId, errorCode);
    g_photoEvents[static_cast<int>(CAM_PHOTO_EVENTS::CAM_PHOTO_CAPTURE_ERR)] = 1;
}

void AppCallback::OnFrameStarted() const
{
    MEDIA_DEBUG_LOG("AppCallback::OnFrameStarted");
    g_previewEvents[static_cast<int>(CAM_PREVIEW_EVENTS::CAM_PREVIEW_FRAME_START)] = 1;
}
void AppCallback::OnFrameEnded(const int32_t frameCount) const
{
    MEDIA_DEBUG_LOG("AppCallback::OnFrameEnded frameCount: %{public}d", frameCount);
    g_previewEvents[static_cast<int>(CAM_PREVIEW_EVENTS::CAM_PREVIEW_FRAME_END)] = 1;
}
void AppCallback::OnError(const int32_t errorCode) const
{
    MEDIA_DEBUG_LOG("AppCallback::OnError errorCode: %{public}d", errorCode);
    g_previewEvents[static_cast<int>(CAM_PREVIEW_EVENTS::CAM_PREVIEW_FRAME_ERR)] = 1;
}
void AppCallback::OnSketchStatusDataChanged(const SketchStatusData& statusData) const
{
    MEDIA_DEBUG_LOG("AppCallback::OnSketchStatusDataChanged");
    g_previewEvents[static_cast<int>(CAM_PREVIEW_EVENTS::CAM_PREVIEW_SKETCH_STATUS_CHANGED)] = 1;
    g_sketchStatus.push_back(static_cast<int32_t>(statusData.status));
}
void AppCallback::OnMacroStatusChanged(MacroStatus status)
{
    MEDIA_DEBUG_LOG("AppCallback::OnMacroStatusChanged");
    if (status == MacroStatus::IDLE) {
        g_macroEvents[static_cast<int>(CAM_MACRO_DETECT_EVENTS::CAM_MACRO_EVENT_IDLE)] = 1;
        g_macroEvents[static_cast<int>(CAM_MACRO_DETECT_EVENTS::CAM_MACRO_EVENT_ACTIVE)] = 0;
    } else if (status == MacroStatus::ACTIVE) {
        g_macroEvents[static_cast<int>(CAM_MACRO_DETECT_EVENTS::CAM_MACRO_EVENT_ACTIVE)] = 1;
        g_macroEvents[static_cast<int>(CAM_MACRO_DETECT_EVENTS::CAM_MACRO_EVENT_IDLE)] = 0;
    }
}

void AppCallback::OnFeatureDetectionStatusChanged(SceneFeature feature, FeatureDetectionStatus status)
{
    MEDIA_DEBUG_LOG("AppCallback::OnFeatureDetectionStatusChanged");
    if (feature == SceneFeature::FEATURE_MOON_CAPTURE_BOOST) {
        if (status == FeatureDetectionStatus::IDLE) {
            g_moonCaptureBoostEvents[static_cast<int>(
                CAM_MOON_CAPTURE_BOOST_EVENTS::CAM_MOON_CAPTURE_BOOST_EVENT_IDLE)] = 1;
            g_moonCaptureBoostEvents[static_cast<int>(
                CAM_MOON_CAPTURE_BOOST_EVENTS::CAM_MOON_CAPTURE_BOOST_EVENT_ACTIVE)] = 0;
        } else if (status == FeatureDetectionStatus::ACTIVE) {
            g_moonCaptureBoostEvents[static_cast<int>(
                CAM_MOON_CAPTURE_BOOST_EVENTS::CAM_MOON_CAPTURE_BOOST_EVENT_ACTIVE)] = 1;
            g_moonCaptureBoostEvents[static_cast<int>(
                CAM_MOON_CAPTURE_BOOST_EVENTS::CAM_MOON_CAPTURE_BOOST_EVENT_IDLE)] = 0;
        }
    }
}

bool AppCallback::IsFeatureSubscribed(SceneFeature feature)
{
    return true;
}

void AppCallback::OnBrightnessStatusChanged(bool state)
{
    MEDIA_DEBUG_LOG("AppCallback::OnBrightnessStatusChanged");
    g_brightnessStatusChanged = true;
}

void AppCallback::OnSlowMotionState(const SlowMotionState state)
{
    MEDIA_DEBUG_LOG("AppCallback::OnSlowMotionState");
    g_slowMotionStatusChanged = true;
}
void AppCallback::OnFoldStatusChanged(const FoldStatusInfo &foldStatusInfo) const
{
    MEDIA_DEBUG_LOG("AppCallback::OnFoldStatusChanged"); 
}

void AppCallback::OnLcdFlashStatusChanged(LcdFlashStatusInfo lcdFlashStatusInfo)
{
    MEDIA_DEBUG_LOG("AppCallback::OnLcdFlashStatusChanged");
}

void AppCallback::OnOfflineDeliveryFinished(const int32_t captureId) const
{
    MEDIA_DEBUG_LOG("AppCallback::OnOfflineDeliveryFinished");
}

void CameraServiceClientUnit::ProcessPreviewProfiles(sptr<CameraOutputCapability>& outputcapability)
{
    previewProfiles.clear();
    std::vector<Profile> tempPreviewProfiles = outputcapability->GetPreviewProfiles();
    for (const auto& profile : tempPreviewProfiles) {
        if ((profile.size_.width == PRVIEW_WIDTH_176 && profile.size_.height == PRVIEW_HEIGHT_144) ||
            (profile.size_.width == PRVIEW_WIDTH_480 && profile.size_.height == PRVIEW_HEIGHT_480) ||
            (profile.size_.width == PRVIEW_WIDTH_640 && profile.size_.height == PRVIEW_WIDTH_640) ||
            (profile.size_.width == PRVIEW_WIDTH_4096 && profile.size_.height == PRVIEW_HEIGHT_3072) ||
            (profile.size_.width == PRVIEW_WIDTH_4160 && profile.size_.height == PRVIEW_HEIGHT_3120) ||
            (profile.size_.width == PRVIEW_WIDTH_8192 && profile.size_.height == PRVIEW_HEIGHT_6144)) {
            MEDIA_DEBUG_LOG("SetUp skip previewProfile width:%{public}d height:%{public}d",
                profile.size_.width, profile.size_.height);
            continue;
        }
        previewProfiles.push_back(profile);
    }

    for (auto i : previewProfiles) {
        MEDIA_DEBUG_LOG("SetUp previewProfiles width:%{public}d height:%{public}d", i.size_.width, i.size_.height);
        previewFormats_.push_back(i.GetCameraFormat());
        previewSizes_.push_back(i.GetSize());
    }
}

sptr<CaptureOutput> CameraServiceClientUnit::CreatePreviewOutput(int32_t width, int32_t height)
{
    sptr<IConsumerSurface> previewSurface = IConsumerSurface::Create();
    sptr<SurfaceListener> listener = new SurfaceListener("Preview", SurfaceType::PREVIEW, g_previewFd, previewSurface);
    previewSurface->RegisterConsumerListener((sptr<IBufferConsumerListener>&)listener);
    Size previewSize;
    previewSize.width = previewProfiles[0].GetSize().width;
    previewSize.height = previewProfiles[0].GetSize().height;
    previewSurface->SetUserData(CameraManager::surfaceFormat, std::to_string(previewProfiles[0].GetCameraFormat()));
    previewSurface->SetDefaultWidthAndHeight(previewSize.width, previewSize.height);

    sptr<IBufferProducer> bp = previewSurface->GetProducer();
    sptr<Surface> pSurface = Surface::CreateSurfaceAsProducer(bp);

    sptr<CaptureOutput> previewOutput = nullptr;
    previewOutput = manager_->CreatePreviewOutput(previewProfiles[0], pSurface);
    return previewOutput;
}

sptr<CaptureOutput> CameraServiceClientUnit::CreatePhotoOutput(int32_t width, int32_t height)
{
    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    CameraFormat photoFormat = photoFormat_;
    Size photoSize;
    photoSize.width = width;
    photoSize.height = height;
    Profile photoProfile = Profile(photoFormat, photoSize);
    sptr<CaptureOutput> photoOutput = nullptr;
    sptr<IBufferProducer> surfaceProducer = surface->GetProducer();
    manager_->CreatePhotoOutput(surfaceProducer);
    photoOutput = manager_->CreatePhotoOutput(photoProfile, surfaceProducer);
    return photoOutput;
}

sptr<CaptureOutput> CameraServiceClientUnit::CreatePreviewOutput()
{
    sptr<CaptureOutput> previewOutput = CreatePreviewOutput(previewWidth_, previewHeight_);
    return previewOutput;
}

sptr<CaptureOutput> CameraServiceClientUnit::CreatePhotoOutput()
{
    sptr<CaptureOutput> photoOutput = CreatePhotoOutput(photoWidth_, photoHeight_);
    return photoOutput;
}

bool CameraServiceClientUnit::IsSupportNow()
{
    const char* deviveTypeString = GetDeviceType();
    std::string deviveType = std::string(deviveTypeString);
    if (deviveType.compare("default") == 0 ||
        (cameras_[0] != nullptr && cameras_[0]->GetConnectionType() == CAMERA_CONNECTION_USB_PLUGIN)) {
        return false;
    }
    return true;
}

void CameraServiceClientUnit::ProcessSize()
{
    Size size = previewSizes_.back();
    previewWidth_ = size.width;
    previewHeight_ = size.height;
    size = photoSizes_.back();
    photoWidth_ = size.width;
    photoHeight_ = size.height;
    size = videoSizes_.back();
    videoWidth_ = size.width;
    videoHeight_ = size.height;

    sptr<CameraInput> camInput = (sptr<CameraInput>&)input_;
    auto device = camInput->GetCameraDevice();
    ASSERT_NE(device, nullptr);
    device->SetMdmCheck(false);
    camInput->Open();
    session_ = manager_->CreateCaptureSession();
    ASSERT_NE(session_, nullptr);
}

void CameraServiceClientUnit::SetUpInit()
{
    previewFormat_ = CAMERA_FORMAT_YUV_420_SP;
    videoFormat_ = CAMERA_FORMAT_YUV_420_SP;
    photoFormat_ = CAMERA_FORMAT_JPEG;
    previewWidth_ = PREVIEW_DEFAULT_WIDTH;
    previewHeight_ = PREVIEW_DEFAULT_HEIGHT;
    photoWidth_ = PHOTO_DEFAULT_WIDTH;
    photoHeight_ = PHOTO_DEFAULT_HEIGHT;
    videoWidth_ = VIDEO_DEFAULT_WIDTH;
    videoHeight_ = VIDEO_DEFAULT_HEIGHT;
}

void CameraServiceClientUnit::SetUpTestCase(void)
{
    MEDIA_INFO_LOG("SetUpTestCase of camera test case!");
    ASSERT_TRUE(TestToken().GetAllCameraPermission());
}

void CameraServiceClientUnit::TearDownTestCase(void)
{
    MEDIA_INFO_LOG("TearDownTestCase of camera test case!");
}

void CameraServiceClientUnit::SetUp()
{
    MEDIA_INFO_LOG("SetUp");
    SetUpInit();
    manager_ = CameraManager::GetInstance();
    ASSERT_NE(manager_, nullptr);
    manager_->SetCallback(std::make_shared<AppCallback>());

    cameras_ = manager_->GetSupportedCameras();
    ASSERT_NE(cameras_.size(), 0);

    input_ = manager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input_, nullptr);
    sptr<CameraManager> camManagerObj = CameraManager::GetInstance();
    std::vector<sptr<CameraDevice>> cameraObjList = camManagerObj->GetSupportedCameras();
    sptr<CameraOutputCapability> outputcapability = camManagerObj->GetSupportedOutputCapability(cameraObjList[0]);
    ASSERT_NE(outputcapability, nullptr);

    ProcessPreviewProfiles(outputcapability);
    if (previewFormats_.empty() || previewSizes_.empty()) {
        g_isSupportedDeviceStatus = true;
        GTEST_SKIP();
    }

    if (std::find(previewFormats_.begin(), previewFormats_.end(), CAMERA_FORMAT_YUV_420_SP) != previewFormats_.end()) {
        previewFormat_ = CAMERA_FORMAT_YUV_420_SP;
    } else {
        previewFormat_ = previewFormats_[0];
    }
    photoProfiles = outputcapability->GetPhotoProfiles();

    for (auto i : photoProfiles) {
        photoFormats_.push_back(i.GetCameraFormat());
        photoSizes_.push_back(i.GetSize());
    }
    ASSERT_TRUE(!photoFormats_.empty());
    ASSERT_TRUE(!photoSizes_.empty());
    photoFormat_ = photoFormats_[0];
    videoProfiles = outputcapability->GetVideoProfiles();

    for (auto i : videoProfiles) {
        videoFormats_.push_back(i.GetCameraFormat());
        videoSizes_.push_back(i.GetSize());
        videoFrameRates_ = i.GetFrameRates();
    }
    ASSERT_TRUE(!videoFormats_.empty());
    ASSERT_TRUE(!videoSizes_.empty());
    ASSERT_TRUE(!videoFrameRates_.empty());
    if (std::find(videoFormats_.begin(), videoFormats_.end(), CAMERA_FORMAT_YUV_420_SP) != videoFormats_.end()) {
        videoFormat_ = CAMERA_FORMAT_YUV_420_SP;
    } else {
        videoFormat_ = videoFormats_[0];
    }
    ProcessSize();
}

void CameraServiceClientUnit::TearDown()
{
    MEDIA_INFO_LOG("TearDown start");
    if (input_) {
        sptr<CameraInput> camInput = (sptr<CameraInput>&)input_;
        camInput->Close();
        input_->Release();
    }
    MEDIA_INFO_LOG("TearDown end");
}

/*
 * Feature: Framework
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: test HCameraDeviceProxy_cpp with anomalous branch
 */
HWTEST_F(CameraServiceClientUnit, camera_service_client_unittest_001, TestSize.Level1)
{
    if (g_isSupportedDeviceStatus) {
        GTEST_SKIP();
    }
    sptr<CameraInput> input_1 = (sptr<CameraInput>&)input_;
    sptr<ICameraDeviceService> deviceObj = input_1->GetCameraDevice();
    ASSERT_NE(deviceObj, nullptr);

    sptr<ICameraDeviceServiceCallback> callback = nullptr;
    int32_t intResult = deviceObj->SetCallback(callback);
    EXPECT_EQ(intResult, 200);

    std::shared_ptr<OHOS::Camera::CameraMetadata> settings = nullptr;
    intResult = deviceObj->UpdateSetting(settings);
    EXPECT_EQ(intResult, 200);

    std::vector<int32_t> results = {};
    intResult = deviceObj->GetEnabledResults(results);
    EXPECT_EQ(intResult, 0);

    deviceObj->EnableResult(results);
    deviceObj->DisableResult(results);
}

/*
 * Feature: Framework
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: test HCameraServiceProxy_cpp with anomalous branch
 */
HWTEST_F(CameraServiceClientUnit, camera_service_client_unittest_002, TestSize.Level1)
{
    if (g_isSupportedDeviceStatus) {
        GTEST_SKIP();
    }
    sptr<IRemoteObject> object = nullptr;
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(samgr, nullptr);

    object = samgr->GetSystemAbility(CAMERA_SERVICE_ID);
    sptr<ICameraService> serviceProxy = iface_cast<ICameraService>(object);
    ASSERT_NE(serviceProxy, nullptr);

    sptr<ICameraServiceCallback> callback = nullptr;
    int32_t intResult = serviceProxy->SetCameraCallback(callback);
    EXPECT_EQ(intResult, 200);

    sptr<ICameraMuteServiceCallback> callback_2 = nullptr;
    intResult = serviceProxy->SetMuteCallback(callback_2);
    EXPECT_EQ(intResult, 200);

    int32_t format = 0;
    int32_t width = 0;
    int32_t height = 0;
    sptr<IStreamCapture> output = nullptr;
    sptr<IBufferProducer> producer = nullptr;
    intResult = serviceProxy->CreatePhotoOutput(producer, format, width, height, output);
    EXPECT_EQ(intResult, 200);

    sptr<IStreamRepeat> output_2 = nullptr;
    intResult = serviceProxy->CreatePreviewOutput(producer, format, width, height, output_2);
    EXPECT_EQ(intResult, 200);

    intResult = serviceProxy->CreateDeferredPreviewOutput(format, width, height, output_2);
    EXPECT_EQ(intResult, 200);

    sptr<IStreamMetadata> output_3 = nullptr;
    intResult = serviceProxy->CreateMetadataOutput(producer, format, {1}, output_3);
    EXPECT_EQ(intResult, 200);

    intResult = serviceProxy->CreateVideoOutput(producer, format, width, height, output_2);
    EXPECT_EQ(intResult, 200);
}

/*
 * Feature: Framework
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: test HCameraServiceProxy_cpp with anomalous branch
 */
HWTEST_F(CameraServiceClientUnit, camera_service_client_unittest_003, TestSize.Level0)
{
    if (g_isSupportedDeviceStatus) {
        GTEST_SKIP();
    }
    int32_t format = 0;
    int32_t width = 0;
    int32_t height = 0;
    std::string cameraId = "";
    std::vector<std::string> cameraIds = {};
    std::vector<std::shared_ptr<OHOS::Camera::CameraMetadata>> cameraAbilityList = {};

    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    sptr<IBufferProducer> producer = surface->GetProducer();

    sptr<IRemoteObject> object = nullptr;
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(samgr, nullptr);

    object = samgr->GetSystemAbility(AUDIO_POLICY_SERVICE_ID);
    sptr<ICameraService> serviceProxy = iface_cast<ICameraService>(object);
    ASSERT_NE(serviceProxy, nullptr);

    sptr<ICameraServiceCallback> callback = manager_->GetCameraStatusListenerManager();
    ASSERT_NE(callback, nullptr);
    int32_t intResult = serviceProxy->SetCameraCallback(callback);
    EXPECT_EQ(intResult, ERR_TRANSACTION_FAILED);

    sptr<ICameraMuteServiceCallback> callback_2 = manager_->GetCameraMuteListenerManager();
    ASSERT_NE(callback_2, nullptr);
    serviceProxy->SetMuteCallback(callback_2);
    EXPECT_EQ(intResult, ERR_TRANSACTION_FAILED);

    intResult = serviceProxy->GetCameras(cameraIds, cameraAbilityList);
    EXPECT_EQ(intResult, ERR_TRANSACTION_FAILED);

    sptr<ICaptureSession> session = nullptr;
    intResult = serviceProxy->CreateCaptureSession(session, 0);
    EXPECT_EQ(intResult, ERR_TRANSACTION_FAILED);

    sptr<IStreamCapture> output = nullptr;
    intResult = serviceProxy->CreatePhotoOutput(producer, format, width, height, output);
    EXPECT_EQ(intResult, ERR_TRANSACTION_FAILED);

    width = PREVIEW_DEFAULT_WIDTH;
    height = PREVIEW_DEFAULT_HEIGHT;
    sptr<IStreamRepeat> output_2 = nullptr;
    intResult = serviceProxy->CreatePreviewOutput(producer, format, width, height, output_2);
    EXPECT_EQ(intResult, ERR_TRANSACTION_FAILED);

    intResult = serviceProxy->CreateDeferredPreviewOutput(format, width, height, output_2);
    EXPECT_EQ(intResult, ERR_TRANSACTION_FAILED);

    sptr<IStreamMetadata> output_3 = nullptr;
    intResult = serviceProxy->CreateMetadataOutput(producer, format, {1}, output_3);
    EXPECT_EQ(intResult, ERR_TRANSACTION_FAILED);

    intResult = serviceProxy->CreateVideoOutput(producer, format, width, height, output_2);
    EXPECT_EQ(intResult, ERR_TRANSACTION_FAILED);

    intResult = serviceProxy->SetListenerObject(object);
    EXPECT_EQ(intResult, ERR_TRANSACTION_FAILED);

    bool muteMode = true;
    intResult = serviceProxy->IsCameraMuted(muteMode);
    EXPECT_EQ(intResult, ERR_TRANSACTION_FAILED);
}

/*
 * Feature: Framework
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: test HCameraDeviceProxy_cpp with anomalous branch
 */
HWTEST_F(CameraServiceClientUnit, camera_service_client_unittest_004, TestSize.Level1)
{
    if (g_isSupportedDeviceStatus) {
        GTEST_SKIP();
    }
    sptr<IRemoteObject> object = nullptr;
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(samgr, nullptr);

    object = samgr->GetSystemAbility(AUDIO_POLICY_SERVICE_ID);

    sptr<ICameraDeviceService> deviceObj = iface_cast<ICameraDeviceService>(object);
    ASSERT_NE(deviceObj, nullptr);

    deviceObj->SetMdmCheck(false);
    int32_t intResult = deviceObj->Open();
    EXPECT_EQ(intResult, ERR_TRANSACTION_FAILED);

    intResult = deviceObj->Close();
    EXPECT_EQ(intResult, ERR_TRANSACTION_FAILED);

    intResult = deviceObj->Release();
    EXPECT_EQ(intResult, ERR_TRANSACTION_FAILED);

    sptr<CameraInput> input = (sptr<CameraInput>&)input_;
    sptr<ICameraDeviceServiceCallback> callback = new (std::nothrow) CameraDeviceServiceCallback(input);
    ASSERT_NE(callback, nullptr);

    intResult = deviceObj->SetCallback(callback);
    EXPECT_EQ(intResult, ERR_TRANSACTION_FAILED);

    std::shared_ptr<OHOS::Camera::CameraMetadata> settings = cameras_[0]->GetMetadata();
    ASSERT_NE(settings, nullptr);

    intResult = deviceObj->UpdateSetting(settings);
    EXPECT_EQ(intResult, ERR_TRANSACTION_FAILED);

    std::vector<int32_t> results = {};
    intResult = deviceObj->GetEnabledResults(results);
    EXPECT_EQ(intResult, ERR_TRANSACTION_FAILED);
}

/*
 * Feature: Framework
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: test HCaptureSessionProxy_cpp with anomalous branch
 */
HWTEST_F(CameraServiceClientUnit, camera_service_client_unittest_005, TestSize.Level1)
{
    if (g_isSupportedDeviceStatus) {
        GTEST_SKIP();
    }
    sptr<IRemoteObject> object = nullptr;
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(samgr, nullptr);

    object = samgr->GetSystemAbility(CAMERA_SERVICE_ID);

    sptr<ICaptureSession> captureSession = iface_cast<ICaptureSession>(object);
    ASSERT_NE(captureSession, nullptr);

    sptr<CaptureOutput> previewOutput = CreatePreviewOutput();
    ASSERT_NE(previewOutput, nullptr);

    sptr<IRemoteObject> stream = nullptr;

    int32_t intResult = captureSession->AddOutput(previewOutput->GetStreamType(), stream);
    EXPECT_EQ(intResult, 200);

    sptr<ICameraDeviceService> cameraDevice = nullptr;
    intResult = captureSession->RemoveInput(cameraDevice);
    EXPECT_EQ(intResult, 200);

    intResult = captureSession->RemoveOutput(previewOutput->GetStreamType(), stream);
    EXPECT_EQ(intResult, 200);

    sptr<ICaptureSessionCallback> callback = nullptr;
    EXPECT_EQ(intResult, 200);
}

/*
 * Feature: Framework
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: test HCaptureSessionProxy_cpp with anomalous branch
 */
HWTEST_F(CameraServiceClientUnit, camera_service_client_unittest_006, TestSize.Level1)
{
    if (g_isSupportedDeviceStatus) {
        GTEST_SKIP();
    }
    sptr<IRemoteObject> object = nullptr;
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(samgr, nullptr);

    object = samgr->GetSystemAbility(AUDIO_POLICY_SERVICE_ID);

    sptr<ICaptureSession> captureSession = iface_cast<ICaptureSession>(object);
    ASSERT_NE(captureSession, nullptr);

    int32_t intResult = captureSession->BeginConfig();
    EXPECT_EQ(intResult, ERR_TRANSACTION_FAILED);

    sptr<CameraInput> input_1 = (sptr<CameraInput>&)input_;
    sptr<ICameraDeviceService> deviceObj = input_1->GetCameraDevice();
    ASSERT_NE(deviceObj, nullptr);

    intResult = captureSession->AddInput(deviceObj);
    EXPECT_EQ(intResult, ERR_TRANSACTION_FAILED);

    sptr<CaptureOutput> previewOutput = CreatePreviewOutput();
    ASSERT_NE(previewOutput, nullptr);
	
    ASSERT_NE(previewOutput->GetStream(), nullptr);
    intResult = captureSession->AddOutput(previewOutput->GetStreamType(), previewOutput->GetStream()->AsObject());
    EXPECT_EQ(intResult, ERR_TRANSACTION_FAILED);

    intResult = captureSession->Start();
    EXPECT_EQ(intResult, ERR_TRANSACTION_FAILED);

    intResult = captureSession->Release();
    EXPECT_EQ(intResult, ERR_TRANSACTION_FAILED);

    sptr<ICaptureSessionCallback> callback = new (std::nothrow) CaptureSessionCallback(session_);
    ASSERT_NE(callback, nullptr);

    intResult = captureSession->SetCallback(callback);
    EXPECT_EQ(intResult, ERR_TRANSACTION_FAILED);

    CaptureSessionState currentState = CaptureSessionState::SESSION_CONFIG_INPROGRESS;
    intResult = captureSession->GetSessionState(currentState);
    EXPECT_EQ(intResult, ERR_TRANSACTION_FAILED);
}

/*
 * Feature: Framework
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: test HStreamCaptureProxy_cpp with anomalous branch
 */
HWTEST_F(CameraServiceClientUnit, camera_service_client_unittest_007, TestSize.Level1)
{
    if (g_isSupportedDeviceStatus) {
        GTEST_SKIP();
    }
    sptr<IRemoteObject> object = nullptr;
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(samgr, nullptr);

    object = samgr->GetSystemAbility(CAMERA_SERVICE_ID);

    sptr<IStreamCapture> capture = iface_cast<IStreamCapture>(object);
    ASSERT_NE(capture, nullptr);

    sptr<IStreamCaptureCallback> callback = nullptr;
    int32_t intResult = capture->SetCallback(callback);
    EXPECT_EQ(intResult, 200);

    bool isEnabled = false;
    intResult = capture->SetThumbnail(isEnabled);
    EXPECT_EQ(intResult, 1);

    intResult = capture->SetThumbnail(isEnabled);
    EXPECT_EQ(intResult, 1);

    std::shared_ptr<OHOS::Camera::CameraMetadata> captureSettings = nullptr;
    intResult = capture->Capture(captureSettings);
    EXPECT_EQ(intResult, 200);
}

/*
 * Feature: Framework
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: test HStreamCaptureProxy_cpp with anomalous branch
 */
HWTEST_F(CameraServiceClientUnit, camera_service_client_unittest_008, TestSize.Level1)
{
    if (g_isSupportedDeviceStatus) {
        GTEST_SKIP();
    }
    sptr<IRemoteObject> object = nullptr;
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(samgr, nullptr);

    object = samgr->GetSystemAbility(AUDIO_POLICY_SERVICE_ID);

    sptr<IStreamCapture> capture = iface_cast<IStreamCapture>(object);
    ASSERT_NE(capture, nullptr);

    std::shared_ptr<OHOS::Camera::CameraMetadata> captureSettings = cameras_[0]->GetMetadata();
    int32_t intResult = capture->Capture(captureSettings);
    EXPECT_EQ(intResult, ERR_TRANSACTION_FAILED);

    intResult = capture->CancelCapture();
    EXPECT_EQ(intResult, ERR_TRANSACTION_FAILED);

    intResult = capture->Release();
    EXPECT_EQ(intResult, ERR_TRANSACTION_FAILED);

    sptr<CaptureOutput> photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);

    sptr<PhotoOutput> photoOutput_1 = (sptr<PhotoOutput>&)photoOutput;
    sptr<IStreamCaptureCallback> callback = new (std::nothrow) HStreamCaptureCallbackImpl(photoOutput_1);
    ASSERT_NE(callback, nullptr);

    intResult = capture->SetCallback(callback);
    EXPECT_EQ(intResult, ERR_TRANSACTION_FAILED);
}

/*
 * Feature: Framework
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: test HStreamMetadataProxy_cpp with anomalous branch
 */
HWTEST_F(CameraServiceClientUnit, camera_service_client_unittest_009, TestSize.Level1)
{
    if (g_isSupportedDeviceStatus) {
        GTEST_SKIP();
    }
    sptr<IRemoteObject> object = nullptr;
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(samgr, nullptr);

    object = samgr->GetSystemAbility(AUDIO_POLICY_SERVICE_ID);

    sptr<IStreamMetadata> metadata = iface_cast<IStreamMetadata>(object);
    ASSERT_NE(metadata, nullptr);

    int32_t intResult = metadata->Start();
    EXPECT_EQ(intResult, ERR_TRANSACTION_FAILED);

    intResult = metadata->Release();
    EXPECT_EQ(intResult, ERR_TRANSACTION_FAILED);
}

/*
 * Feature: Framework
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: test HStreamRepeatProxy_cpp with anomalous branch
 */
HWTEST_F(CameraServiceClientUnit, camera_service_client_unittest_010, TestSize.Level1)
{
    if (g_isSupportedDeviceStatus) {
        GTEST_SKIP();
    }
    sptr<IRemoteObject> object = nullptr;
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(samgr, nullptr);

    object = samgr->GetSystemAbility(CAMERA_SERVICE_ID);

    sptr<IStreamRepeat> repeat = iface_cast<IStreamRepeat>(object);
    ASSERT_NE(repeat, nullptr);

    sptr<IStreamRepeatCallback> callback = nullptr;
    int32_t intResult = repeat->SetCallback(callback);
    EXPECT_EQ(intResult, 200);

    sptr<OHOS::IBufferProducer> producer = nullptr;
    intResult = repeat->AddDeferredSurface(producer);
    EXPECT_EQ(intResult, 200);

    object = samgr->GetSystemAbility(AUDIO_POLICY_SERVICE_ID);

    repeat = iface_cast<IStreamRepeat>(object);
    ASSERT_NE(repeat, nullptr);

    sptr<CaptureOutput> previewOutput = CreatePreviewOutput();
    ASSERT_NE(previewOutput, nullptr);

    sptr<PreviewOutput> previewOutput_1 = (sptr<PreviewOutput>&)previewOutput;
    callback = previewOutput_1->GetPreviewOutputListenerManager();
    ASSERT_NE(callback, nullptr);

    intResult = repeat->SetCallback(callback);
    EXPECT_EQ(intResult, ERR_TRANSACTION_FAILED);

    sptr<IConsumerSurface> previewSurface = IConsumerSurface::Create();
    producer = previewSurface->GetProducer();

    intResult = repeat->AddDeferredSurface(producer);
    EXPECT_EQ(intResult, ERR_TRANSACTION_FAILED);
}

/*
 * Feature: Framework
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: test CallbackProxy_cpp with anomalous branch
 */
HWTEST_F(CameraServiceClientUnit, camera_service_client_unittest_011, TestSize.Level1)
{
    if (g_isSupportedDeviceStatus) {
        GTEST_SKIP();
    }
    sptr<IRemoteObject> object = nullptr;
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(samgr, nullptr);

    object = samgr->GetSystemAbility(CAMERA_SERVICE_ID);

    sptr<CameraInput> input = (sptr<CameraInput>&)input_;
    sptr<ICameraDeviceServiceCallback> callback = new (std::nothrow) CameraDeviceServiceCallback(input);
    ASSERT_NE(callback, nullptr);

    sptr<CameraDeviceServiceCallbackProxy> deviceCallback = (sptr<CameraDeviceServiceCallbackProxy>&)callback;
    deviceCallback = new (std::nothrow) CameraDeviceServiceCallbackProxy(object);
    ASSERT_NE(deviceCallback, nullptr);

    uint64_t timestamp = 10;
    std::shared_ptr<OHOS::Camera::CameraMetadata> result = nullptr;
    int32_t intResult = deviceCallback->OnResult(timestamp, result);
    EXPECT_EQ(intResult, 200);
}

/*
 * Feature: Framework
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: test prelaunch the camera with serviceProxy_ null anomalous branch
 */
HWTEST_F(CameraServiceClientUnit, camera_service_client_unittest_012, TestSize.Level1)
{
    if (g_isSupportedDeviceStatus) {
        GTEST_SKIP();
    }
    sptr<CameraManager> camManagerObj = CameraManager::GetInstance();
    ASSERT_NE(camManagerObj, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput>&)input_;
    std::string cameraId = camInput->GetCameraId();
    int activeTime = 0;
    EffectParam effectParam = {0, 0, 0};

    int32_t intResult = camManagerObj->SetPrelaunchConfig(cameraId, RestoreParamTypeOhos::TRANSIENT_ACTIVE_PARAM_OHOS,
        activeTime, effectParam);
    if (!IsSupportNow()) {
        EXPECT_EQ(intResult, 7400201);
    } else {
        EXPECT_EQ(intResult, 0);
    }

    intResult = camManagerObj->PrelaunchCamera(0);
    EXPECT_EQ(intResult, 7400201);
    // CameraManager instance has been changed, need recover
    camManagerObj->SetServiceProxy(nullptr);

    intResult = camManagerObj->PrelaunchCamera(0);
    EXPECT_EQ(intResult, 7400201);

    bool isPreLaunchSupported = camManagerObj->IsPrelaunchSupported(cameras_[0]);
    if (!IsSupportNow()) {
        EXPECT_EQ(isPreLaunchSupported, false);
    } else {
        EXPECT_EQ(isPreLaunchSupported, true);
    }

    intResult = camManagerObj->SetPrelaunchConfig(cameraId, RestoreParamTypeOhos::TRANSIENT_ACTIVE_PARAM_OHOS,
        activeTime, effectParam);
    EXPECT_EQ(intResult, 7400201);
    // CameraManager recovered
    camManagerObj->InitCameraManager();
}

/*
 * Feature: Framework
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: test serviceProxy_ null with anomalous branch
 */
HWTEST_F(CameraServiceClientUnit, camera_service_client_unittest_013, TestSize.Level1)
{
    if (g_isSupportedDeviceStatus) {
        GTEST_SKIP();
    }
    sptr<Surface> pSurface = nullptr;
    sptr<IBufferProducer> surfaceProducer = nullptr;

    sptr<CameraManager> camManagerObj = CameraManager::GetInstance();
    ASSERT_NE(camManagerObj, nullptr);

    // CameraManager instance has been changed, need recover
    camManagerObj->ClearCameraDeviceListCache();

    std::vector<sptr<CameraDevice>> camdeviceObj_1 = camManagerObj->GetSupportedCameras();
    ASSERT_TRUE(camdeviceObj_1.size() != 0);

    camManagerObj->SetServiceProxy(nullptr);

    sptr<CaptureSession> captureSession = camManagerObj->CreateCaptureSession();
    EXPECT_EQ(captureSession, nullptr);

    sptr<CaptureOutput> metadataOutput = camManagerObj->CreateMetadataOutput();
    EXPECT_EQ(metadataOutput, nullptr);

    sptr<CaptureOutput> previewOutput = camManagerObj->CreatePreviewOutput(previewProfiles[0], pSurface);
    EXPECT_EQ(previewOutput, nullptr);

    previewOutput = camManagerObj->CreateDeferredPreviewOutput(previewProfiles[0]);
    EXPECT_EQ(previewOutput, nullptr);

    sptr<CaptureOutput> photoOutput = camManagerObj->CreatePhotoOutput(photoProfiles[0], surfaceProducer);
    EXPECT_EQ(photoOutput, nullptr);

    sptr<CaptureOutput> videoOutput = camManagerObj->CreateVideoOutput(videoProfiles[0], pSurface);
    EXPECT_EQ(videoOutput, nullptr);
    // CameraManager recovered
    camManagerObj->InitCameraManager();
}

/*
 * Feature: Framework
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: test serviceProxy_ null with muteCamera anomalous branch
 */
HWTEST_F(CameraServiceClientUnit, camera_service_client_unittest_014, TestSize.Level1)
{
    if (g_isSupportedDeviceStatus) {
        GTEST_SKIP();
    }
    sptr<CameraManager> camManagerObj = CameraManager::GetInstance();
    ASSERT_NE(camManagerObj, nullptr);

    // CameraManager instance has been changed, need recover
    camManagerObj->SetServiceProxy(nullptr);

    bool cameraMuted = camManagerObj->IsCameraMuted();
    EXPECT_EQ(cameraMuted, false);

    camManagerObj->ClearCameraDeviceListCache();
    camManagerObj->CacheCameraDeviceAbilitySupportValue(
        CameraManager::CAMERA_ABILITY_SUPPORT_MUTE, true);
    bool cameraMuteSupported = camManagerObj->IsCameraMuteSupported();
    EXPECT_EQ(cameraMuteSupported, true);

    camManagerObj->MuteCamera(cameraMuted);
    // CameraManager recovered
    camManagerObj->InitCameraManager();
}

/*
 * Feature: Framework
 * Function: Test errorCode
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: test errorCode with abnormal branches
 */
HWTEST_F(CameraServiceClientUnit, camera_service_client_unittest_015, TestSize.Level1)
{
    if (g_isSupportedDeviceStatus) {
        GTEST_SKIP();
    }
    sptr<IRemoteObject> object = nullptr;
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(samgr, nullptr);
    object = samgr->GetSystemAbility(AUDIO_POLICY_SERVICE_ID);
    sptr<CameraServiceProxy> hCameraServiceProxy = new (std::nothrow) CameraServiceProxy(object);
    ASSERT_NE(hCameraServiceProxy, nullptr);
    EffectParam effectParam = {0, 0, 0};

    sptr<ICameraDeviceService> device = nullptr;
    sptr<ITorchServiceCallback> torchSvcCallback = nullptr;
    bool canOpenCamera = true;
    EXPECT_EQ(hCameraServiceProxy->CreateCameraDevice(cameras_[0]->GetID(), device), ERR_TRANSACTION_FAILED);
    hCameraServiceProxy->SetTorchCallback(torchSvcCallback);
    sptr<CameraManager> camManagerObj = CameraManager::GetInstance();
    torchSvcCallback =  camManagerObj->GetTorchServiceListenerManager();
    ASSERT_NE(torchSvcCallback, nullptr);
    hCameraServiceProxy->SetTorchCallback(torchSvcCallback);
    hCameraServiceProxy->MuteCamera(true);
    hCameraServiceProxy->MuteCamera(false);
    hCameraServiceProxy->PrelaunchCamera(0);
    hCameraServiceProxy->SetPrelaunchConfig(cameras_[0]->GetID(),
        RestoreParamTypeOhos::NO_NEED_RESTORE_PARAM_OHOS, 0, effectParam);
    hCameraServiceProxy->SetTorchLevel(0);
    hCameraServiceProxy->AllowOpenByOHSide(cameras_[0]->GetID(), 0, canOpenCamera);
    hCameraServiceProxy->NotifyCameraState(cameras_[0]->GetID(), 0);
}

/*
 * Feature: Framework
 * Function: Test errorCode
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: test errorCode with abnormal branches
 */
HWTEST_F(CameraServiceClientUnit, camera_service_client_unittest_016, TestSize.Level1)
{
    if (g_isSupportedDeviceStatus) {
        GTEST_SKIP();
    }
    sptr<IRemoteObject> object = nullptr;
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(samgr, nullptr);
    object = samgr->GetSystemAbility(CAMERA_SERVICE_ID);
    sptr<CameraServiceCallbackProxy> hCameraServiceCallbackProxy =
        new (std::nothrow) CameraServiceCallbackProxy(object);
    ASSERT_NE(hCameraServiceCallbackProxy, nullptr);
    sptr<CameraMuteServiceCallbackProxy> hCameraMuteServiceCallbackProxy =
        new (std::nothrow) CameraMuteServiceCallbackProxy(object);
    ASSERT_NE(hCameraMuteServiceCallbackProxy, nullptr);
    sptr<TorchServiceCallbackProxy> hTorchServiceCallbackProxy = new (std::nothrow) TorchServiceCallbackProxy(object);
    ASSERT_NE(hTorchServiceCallbackProxy, nullptr);

    hCameraServiceCallbackProxy->OnFlashlightStatusChanged(cameras_[0]->GetID(),
        static_cast<int32_t>(FlashStatus::FLASH_STATUS_OFF));
    hCameraMuteServiceCallbackProxy->OnCameraMute(true);
    hCameraMuteServiceCallbackProxy->OnCameraMute(false);
    hTorchServiceCallbackProxy->OnTorchStatusChange(TorchStatus::TORCH_STATUS_OFF);
}

/*
 * Feature: Framework
 * Function: Test errorCode, width and height, if sketchRatio > SKETCH_RATIO_MAX_VALUE
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: test errorCode, width and height, if sketchRatio > SKETCH_RATIO_MAX_VALUE with abnormal branches
 */
HWTEST_F(CameraServiceClientUnit, camera_service_client_unittest_017, TestSize.Level1)
{
    if (g_isSupportedDeviceStatus) {
        GTEST_SKIP();
    }
    sptr<IRemoteObject> object = nullptr;
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(samgr, nullptr);
    object = samgr->GetSystemAbility(CAMERA_SERVICE_ID);
    sptr<IStreamRepeat> repeat = iface_cast<IStreamRepeat>(object);
    ASSERT_NE(repeat, nullptr);
    sptr<StreamRepeatProxy> hStreamRepeatProxy = new (std::nothrow) StreamRepeatProxy(object);
    ASSERT_NE(hStreamRepeatProxy, nullptr);

    hStreamRepeatProxy->ForkSketchStreamRepeat(0, 0, object, 0);
    hStreamRepeatProxy->ForkSketchStreamRepeat(1, 0, object, 0);
    hStreamRepeatProxy->ForkSketchStreamRepeat(1, 1, object, 0);
    hStreamRepeatProxy->UpdateSketchRatio(0.0f);
    hStreamRepeatProxy->UpdateSketchRatio(200.0f);
    hStreamRepeatProxy->UpdateSketchRatio(90.0f);
    hStreamRepeatProxy->RemoveSketchStreamRepeat();
}

/*
 * Feature: Framework
 * Function: Test errorCode, width and height, if sketchRatio > SKETCH_RATIO_MAX_VALUE
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: test errorCode, width and height, if sketchRatio > SKETCH_RATIO_MAX_VALUE with abnormal branches
 */
HWTEST_F(CameraServiceClientUnit, camera_service_client_unittest_018, TestSize.Level1)
{
    if (g_isSupportedDeviceStatus) {
        GTEST_SKIP();
    }
    sptr<IRemoteObject> object = nullptr;
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(samgr, nullptr);
    object = samgr->GetSystemAbility(AUDIO_POLICY_SERVICE_ID);
    sptr<IStreamRepeat> repeat = iface_cast<IStreamRepeat>(object);
    ASSERT_NE(repeat, nullptr);
    sptr<StreamRepeatProxy> hStreamRepeatProxy = new (std::nothrow) StreamRepeatProxy(object);
    ASSERT_NE(hStreamRepeatProxy, nullptr);

    hStreamRepeatProxy->UpdateSketchRatio(0.0f);
    hStreamRepeatProxy->UpdateSketchRatio(200.0f);
    hStreamRepeatProxy->UpdateSketchRatio(90.0f);
    hStreamRepeatProxy->RemoveSketchStreamRepeat();
}

/*
 * Feature: Framework
 * Function: Test errorCode
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: test errorCode with abnormal branches
 */
HWTEST_F(CameraServiceClientUnit, camera_service_client_unittest_019, TestSize.Level1)
{
    if (g_isSupportedDeviceStatus) {
        GTEST_SKIP();
    }
    sptr<IRemoteObject> object = nullptr;
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(samgr, nullptr);
    object = samgr->GetSystemAbility(CAMERA_SERVICE_ID);
    sptr<StreamCaptureCallbackProxy> hStreamCaptureCallbackProxy =
        new (std::nothrow) StreamCaptureCallbackProxy(object);
    ASSERT_NE(hStreamCaptureCallbackProxy, nullptr);

    hStreamCaptureCallbackProxy->OnCaptureStarted(0);
    hStreamCaptureCallbackProxy->OnCaptureStarted(0, 0);
    hStreamCaptureCallbackProxy->OnCaptureEnded(0, 0);
    hStreamCaptureCallbackProxy->OnCaptureError(0, 0);
    hStreamCaptureCallbackProxy->OnFrameShutter(0, 0);
    hStreamCaptureCallbackProxy->OnFrameShutterEnd(0, 0);
    hStreamCaptureCallbackProxy->OnCaptureReady(0, 0);
}

/*
 * Feature: Framework
 * Function: Test errorCode
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: test errorCode with abnormal branches
 */
HWTEST_F(CameraServiceClientUnit, camera_service_client_unittest_020, TestSize.Level1)
{
    if (g_isSupportedDeviceStatus) {
        GTEST_SKIP();
    }
    sptr<IRemoteObject> object = nullptr;
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(samgr, nullptr);
    object = samgr->GetSystemAbility(CAMERA_SERVICE_ID);
    sptr<StreamRepeatCallbackProxy> hStreamRepeatCallbackProxy = new (std::nothrow) StreamRepeatCallbackProxy(object);
    ASSERT_NE(hStreamRepeatCallbackProxy, nullptr);

    hStreamRepeatCallbackProxy->OnSketchStatusChanged(SketchStatus::STOPED);
    hStreamRepeatCallbackProxy->OnFrameStarted();
    hStreamRepeatCallbackProxy->OnFrameEnded(0);
    hStreamRepeatCallbackProxy->OnFrameError(0);
}

/*
 * Feature: Framework
 * Function: Test errorCode
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: test errorCode with abnormal branches
 */
HWTEST_F(CameraServiceClientUnit, camera_service_client_unittest_021, TestSize.Level1)
{
    if (g_isSupportedDeviceStatus) {
        GTEST_SKIP();
    }
    sptr<IRemoteObject> object = nullptr;
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(samgr, nullptr);
    object = samgr->GetSystemAbility(CAMERA_SERVICE_ID);
    sptr<CaptureSessionCallbackProxy> hCaptureSessionCallbackProxy =
        new (std::nothrow) CaptureSessionCallbackProxy(object);
    ASSERT_NE(hCaptureSessionCallbackProxy, nullptr);
    hCaptureSessionCallbackProxy->OnError(0);
}

/*
 * Feature: Framework
 * Function: Test errorCode
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: test errorCode with abnormal branches
 */
HWTEST_F(CameraServiceClientUnit, camera_service_client_unittest_022, TestSize.Level1)
{
    if (g_isSupportedDeviceStatus) {
        GTEST_SKIP();
    }
    sptr<IRemoteObject> object = nullptr;
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(samgr, nullptr);
    object = samgr->GetSystemAbility(CAMERA_SERVICE_ID);
    sptr<CameraServiceProxy> hCameraServiceProxy = new (std::nothrow) CameraServiceProxy(object);
    ASSERT_NE(hCameraServiceProxy, nullptr);
    EffectParam effectParam = {0, 0, 0};

    sptr<ICameraDeviceService> device = nullptr;
    sptr<ITorchServiceCallback> torchSvcCallback = nullptr;
    hCameraServiceProxy->CreateCameraDevice(cameras_[0]->GetID(), device);
    hCameraServiceProxy->SetTorchCallback(torchSvcCallback);
    torchSvcCallback = manager_->GetTorchServiceListenerManager();
    ASSERT_NE(torchSvcCallback, nullptr);
    hCameraServiceProxy->SetTorchCallback(torchSvcCallback);
    hCameraServiceProxy->MuteCamera(true);
    hCameraServiceProxy->MuteCamera(false);
    hCameraServiceProxy->PrelaunchCamera(0);
    hCameraServiceProxy->SetPrelaunchConfig(cameras_[0]->GetID(),
        RestoreParamTypeOhos::NO_NEED_RESTORE_PARAM_OHOS, 0, effectParam);
    hCameraServiceProxy->SetTorchLevel(0);
}

/*
 * Feature: Framework
 * Function: Test errorCode
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: test errorCode with abnormal branches
 */
HWTEST_F(CameraServiceClientUnit, camera_service_client_unittest_023, TestSize.Level1)
{
    if (g_isSupportedDeviceStatus) {
        GTEST_SKIP();
    }
    sptr<IRemoteObject> object = nullptr;
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(samgr, nullptr);
    object = samgr->GetSystemAbility(AUDIO_POLICY_SERVICE_ID);
    sptr<CameraServiceCallbackProxy> hCameraServiceCallbackProxy =
        new (std::nothrow) CameraServiceCallbackProxy(object);
    ASSERT_NE(hCameraServiceCallbackProxy, nullptr);
    sptr<CameraMuteServiceCallbackProxy> hCameraMuteServiceCallbackProxy =
        new (std::nothrow) CameraMuteServiceCallbackProxy(object);
    ASSERT_NE(hCameraMuteServiceCallbackProxy, nullptr);
    sptr<TorchServiceCallbackProxy> hTorchServiceCallbackProxy = new (std::nothrow) TorchServiceCallbackProxy(object);
    ASSERT_NE(hTorchServiceCallbackProxy, nullptr);

    hCameraServiceCallbackProxy->OnFlashlightStatusChanged(cameras_[0]->GetID(),
        static_cast<int32_t>(FlashStatus::FLASH_STATUS_OFF));
    hCameraMuteServiceCallbackProxy->OnCameraMute(true);
    hCameraMuteServiceCallbackProxy->OnCameraMute(false);
    hTorchServiceCallbackProxy->OnTorchStatusChange(TorchStatus::TORCH_STATUS_OFF);
}

/*
 * Feature: Framework
 * Function: Test errorCode
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: test errorCode with abnormal branches
 */
HWTEST_F(CameraServiceClientUnit, camera_service_client_unittest_024, TestSize.Level1)
{
    if (g_isSupportedDeviceStatus) {
        GTEST_SKIP();
    }
    sptr<IRemoteObject> object = nullptr;
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(samgr, nullptr);
    object = samgr->GetSystemAbility(AUDIO_POLICY_SERVICE_ID);
    sptr<StreamCaptureCallbackProxy> hStreamCaptureCallbackProxy =
        new (std::nothrow) StreamCaptureCallbackProxy(object);
    ASSERT_NE(hStreamCaptureCallbackProxy, nullptr);

    hStreamCaptureCallbackProxy->OnCaptureStarted(0);
    hStreamCaptureCallbackProxy->OnCaptureStarted(0, 0);
    hStreamCaptureCallbackProxy->OnCaptureEnded(0, 0);
    hStreamCaptureCallbackProxy->OnCaptureError(0, 0);
    hStreamCaptureCallbackProxy->OnFrameShutter(0, 0);
    hStreamCaptureCallbackProxy->OnFrameShutterEnd(0, 0);
    hStreamCaptureCallbackProxy->OnCaptureReady(0, 0);
}

/*
 * Feature: Framework
 * Function: Test errorCode
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: test errorCode with abnormal branches
 */
HWTEST_F(CameraServiceClientUnit, camera_service_client_unittest_025, TestSize.Level1)
{
    if (g_isSupportedDeviceStatus) {
        GTEST_SKIP();
    }
    sptr<IRemoteObject> object = nullptr;
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(samgr, nullptr);
    object = samgr->GetSystemAbility(AUDIO_POLICY_SERVICE_ID);
    sptr<StreamRepeatCallbackProxy> hStreamRepeatCallbackProxy = new (std::nothrow) StreamRepeatCallbackProxy(object);
    ASSERT_NE(hStreamRepeatCallbackProxy, nullptr);

    hStreamRepeatCallbackProxy->OnSketchStatusChanged(SketchStatus::STOPED);
    hStreamRepeatCallbackProxy->OnFrameStarted();
    hStreamRepeatCallbackProxy->OnFrameEnded(0);
    hStreamRepeatCallbackProxy->OnFrameError(0);
}

/*
 * Feature: Framework
 * Function: Test errorCode
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: test errorCode with abnormal branches
 */
HWTEST_F(CameraServiceClientUnit, camera_service_client_unittest_026, TestSize.Level1)
{
    if (g_isSupportedDeviceStatus) {
        GTEST_SKIP();
    }
    sptr<IRemoteObject> object = nullptr;
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(samgr, nullptr);
    object = samgr->GetSystemAbility(AUDIO_POLICY_SERVICE_ID);
    sptr<CaptureSessionCallbackProxy> hCaptureSessionCallbackProxy =
        new (std::nothrow) CaptureSessionCallbackProxy(object);
    ASSERT_NE(hCaptureSessionCallbackProxy, nullptr);
    hCaptureSessionCallbackProxy->OnError(0);
}

/*
 * Feature: Framework
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: test ResetRssPriority the camera with serviceProxy_ null anomalous branch
 */
HWTEST_F(CameraServiceClientUnit, camera_service_client_unittest_027, TestSize.Level0)
{
    if (g_isSupportedDeviceStatus) {
        GTEST_SKIP();
    }
    sptr<CameraManager> camManagerObj = CameraManager::GetInstance();
    ASSERT_NE(camManagerObj, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput>&)input_;
    std::string cameraId = camInput->GetCameraId();
    int activeTime = 0;
    EffectParam effectParam = {0, 0, 0};

    int32_t intResult = camManagerObj->SetPrelaunchConfig(cameraId, RestoreParamTypeOhos::TRANSIENT_ACTIVE_PARAM_OHOS,
        activeTime, effectParam);
    if (!IsSupportNow()) {
        EXPECT_EQ(intResult, 7400201);
    } else {
        EXPECT_EQ(intResult, 0);
    }

    intResult = camManagerObj->ResetRssPriority();
    EXPECT_EQ(intResult, 0);
    // CameraManager instance has been changed, need recover
    camManagerObj->SetServiceProxy(nullptr);

    intResult = camManagerObj->ResetRssPriority();
    EXPECT_EQ(intResult, 7400201);
}

}
}