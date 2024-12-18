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

#include "hcamera_service_unittest.h"
#include "gtest/gtest.h"
#include <cstdint>
#include <vector>
#include "access_token.h"
#include "accesstoken_kit.h"
#include "camera_log.h"
#include "camera_manager.h"
#include "camera_util.h"
#include "gmock/gmock.h"
#include "input/camera_input.h"
#include "ipc_skeleton.h"
#include "nativetoken_kit.h"
#include "slow_motion_session.h"
#include "surface.h"
#include "token_setproc.h"
#include "os_account_manager.h"

using namespace testing::ext;

namespace OHOS {
namespace CameraStandard {
using namespace OHOS::HDI::Camera::V1_1;

const uint32_t METADATA_ITEM_SIZE = 20;
const uint32_t METADATA_DATA_SIZE = 200;
const std::string LOCAL_SERVICE_NAME = "camera_service";

sptr<HCameraHostManager> HCameraServiceUnit::cameraHostManager_ = nullptr;

void HCameraServiceUnit::SetUpTestCase(void)
{
    cameraHostManager_ = new(std::nothrow) HCameraHostManager(nullptr);
}

void HCameraServiceUnit::TearDownTestCase(void)
{
    if (cameraHostManager_) {
        cameraHostManager_ = nullptr;
    }
}

void HCameraServiceUnit::SetUp()
{
    NativeAuthorization();
    cameraService_ = new(std::nothrow) HCameraService(cameraHostManager_);
    ASSERT_NE(cameraService_, nullptr);
    cameraManager_ = CameraManager::GetInstance();
    ASSERT_NE(cameraManager_, nullptr);
}

void HCameraServiceUnit::TearDown()
{
    if (cameraService_) {
        cameraService_ = nullptr;
    }
    if (cameraManager_) {
        cameraManager_ = nullptr;
    }
}

void HCameraServiceUnit::NativeAuthorization()
{
    const char *perms[3];
    perms[0] = "ohos.permission.DISTRIBUTED_DATASYNC";
    perms[1] = "ohos.permission.CAMERA";
    perms[2] = "ohos.permission.CAMERA_CONTROL";
    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = 3,
        .aclsNum = 0,
        .dcaps = NULL,
        .perms = perms,
        .acls = NULL,
        .processName = "native_camera_tdd",
        .aplStr = "system_basic",
    };
    tokenId_ = GetAccessTokenId(&infoInstance);
    uid_ = IPCSkeleton::GetCallingUid();
    AccountSA::OsAccountManager::GetOsAccountLocalIdFromUid(uid_, userId_);
    MEDIA_DEBUG_LOG("HCameraServiceUnit::NativeAuthorization uid:%{public}d", uid_);
    SetSelfTokenID(tokenId_);
    OHOS::Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
}

/*
 * Feature: CameraService
 * Function: Test constructor with an argument as sptr<HCameraHostManager> in class HCameraService
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test constructor with an argument as sptr<HCameraHostManager>
 */
HWTEST_F(HCameraServiceUnit, HCamera_service_unittest_001, TestSize.Level0)
{
    ASSERT_NE(cameraService_, nullptr);
    cameraService_->cameraDataShareHelper_ = nullptr;
    cameraService_->OnStart();
    EXPECT_NE(cameraService_->cameraDataShareHelper_, nullptr);
    cameraService_->OnDump();
    cameraService_->isFoldRegister = true;
    cameraService_->OnStop();
    EXPECT_FALSE(cameraService_->isFoldRegister);
}

/*
 * Feature: CameraService
 * Function: Test CreatePhotoOutput in class HCameraService
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CreatePhotoOutput when height or width equals 0,returns CAMERA_INVALID_ARG
 */
HWTEST_F(HCameraServiceUnit, HCamera_service_unittest_002, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_FALSE(cameras.empty());
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    std::string cameraId = cameras[0]->GetID();
    cameraHostManager_->OpenCameraDevice(cameraId, nullptr, pDevice_, true);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    camInput->GetCameraDevice()->Open();

    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    sptr<IBufferProducer> producer = surface->GetProducer();
    sptr<IStreamCapture> output_1 = nullptr;

    int32_t height = 0;
    int32_t width = PHOTO_DEFAULT_WIDTH;
    int32_t intResult = cameraService_->CreatePhotoOutput(producer, 0, width, height, output_1);
    EXPECT_EQ(intResult, CAMERA_INVALID_ARG);

    width = 0;
    height = PHOTO_DEFAULT_HEIGHT;
    intResult = cameraService_->CreatePhotoOutput(producer, 0, width, height, output_1);
    EXPECT_EQ(intResult, CAMERA_INVALID_ARG);

    input->Close();
}

/*
 * Feature: CameraService
 * Function: Test CreatePreviewOutput in class HCameraService
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CreatePreviewOutput,when height or width equals 0,returns CAMERA_INVALID_ARG
 */
HWTEST_F(HCameraServiceUnit, HCamera_service_unittest_003, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_FALSE(cameras.empty());
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    std::string cameraId = cameras[0]->GetID();
    cameraHostManager_->OpenCameraDevice(cameraId, nullptr, pDevice_, true);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    camInput->GetCameraDevice()->Open();

    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    sptr<IBufferProducer> producer = surface->GetProducer();

    int32_t width = PREVIEW_DEFAULT_WIDTH;
    int32_t height = 0;
    sptr<IStreamRepeat> output = nullptr;

    int32_t intResult = cameraService_->CreatePreviewOutput(producer, 0, width, height, output);
    EXPECT_EQ(intResult, CAMERA_INVALID_ARG);

    width = 0;
    intResult = cameraService_->CreatePreviewOutput(producer, 0, width, height, output);
    EXPECT_EQ(intResult, CAMERA_INVALID_ARG);
    input->Close();
}

/*
 * Feature: CameraService
 * Function: Test CreateDepthDataOutput in class HCameraService
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CreateDepthDataOutput,when height or width equals 0,or producer equals nullptr,
 *                  returns CAMERA_INVALID_ARG,in normal branch,returns CAMERA_OK
 */
HWTEST_F(HCameraServiceUnit, HCamera_service_unittest_004, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_FALSE(cameras.empty());
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    std::string cameraId = cameras[0]->GetID();
    cameraHostManager_->OpenCameraDevice(cameraId, nullptr, pDevice_, true);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    camInput->GetCameraDevice()->Open();

    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    sptr<IBufferProducer> producer = surface->GetProducer();

    int32_t height = 0;
    int32_t width = PHOTO_DEFAULT_WIDTH;
    sptr<IStreamDepthData> output = nullptr;

    int32_t intResult = cameraService_->CreateDepthDataOutput(producer, 0, width, height, output);
    EXPECT_EQ(intResult, CAMERA_INVALID_ARG);

    height = PHOTO_DEFAULT_HEIGHT;
    width = 0;
    intResult = cameraService_->CreateDepthDataOutput(producer, 0, width, height, output);
    EXPECT_EQ(intResult, CAMERA_INVALID_ARG);

    width = PHOTO_DEFAULT_WIDTH;
    producer = nullptr;
    intResult = cameraService_->CreateDepthDataOutput(producer, 0, width, height, output);
    EXPECT_EQ(intResult, CAMERA_INVALID_ARG);

    producer = surface->GetProducer();
    width = PHOTO_DEFAULT_WIDTH;
    height = PHOTO_DEFAULT_HEIGHT;

    intResult = cameraService_->CreateDepthDataOutput(producer, 0, width, height, output);
    EXPECT_EQ(intResult, CAMERA_OK);

    input->Close();
}

/*
 * Feature: CameraService
 * Function: Test CreateVideoOutput in class HCameraService
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CreateVideoOutput,when height or width equals 0,or producer equals nullptr,
 *                  returns CAMERA_INVALID_ARG
 */
HWTEST_F(HCameraServiceUnit, HCamera_service_unittest_005, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_FALSE(cameras.empty());

    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);

    std::string cameraId = cameras[0]->GetID();
    cameraHostManager_->OpenCameraDevice(cameraId, nullptr, pDevice_, true);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    camInput->GetCameraDevice()->Open();

    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    sptr<IBufferProducer> producer = surface->GetProducer();

    int32_t height = 0;
    int32_t width = PHOTO_DEFAULT_WIDTH;
    sptr<IStreamRepeat> output = nullptr;
    int32_t intResult = cameraService_->CreateVideoOutput(producer, 0, width, height, output);
    EXPECT_EQ(intResult, CAMERA_INVALID_ARG);

    width = 0;
    intResult = cameraService_->CreateVideoOutput(producer, 0, width, height, output);
    EXPECT_EQ(intResult, CAMERA_INVALID_ARG);

    producer = nullptr;
    intResult = cameraService_->CreateVideoOutput(producer, 0, width, height, output);
    EXPECT_EQ(intResult, CAMERA_INVALID_ARG);

    producer = surface->GetProducer();
    width = PHOTO_DEFAULT_WIDTH;
    height = PHOTO_DEFAULT_HEIGHT;
    intResult = cameraService_->CreateVideoOutput(producer, 0, width, height, output);
    EXPECT_EQ(intResult, CAMERA_OK);

    input->Close();
}

/*
 * Feature: CameraService
 * Function: Test OnFoldStatusChanged in class HCameraService
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test OnFoldStatusChanged,after executing OnFoldStatusChanged,the value of private member
 *                  preFoldStatus_ will be changed
 */
HWTEST_F(HCameraServiceUnit, HCamera_service_unittest_006, TestSize.Level0)
{
    OHOS::Rosen::FoldStatus foldStatus = OHOS::Rosen::FoldStatus::HALF_FOLD;
    cameraService_->preFoldStatus_ = FoldStatus::EXPAND;
    cameraService_->OnFoldStatusChanged(foldStatus);
    EXPECT_EQ(cameraService_->preFoldStatus_, FoldStatus::HALF_FOLD);

    foldStatus = OHOS::Rosen::FoldStatus::EXPAND;
    cameraService_->preFoldStatus_ = FoldStatus::HALF_FOLD;
    cameraService_->OnFoldStatusChanged(foldStatus);
    EXPECT_EQ(cameraService_->preFoldStatus_, FoldStatus::EXPAND);
}

/*
 * Feature: CameraService
 * Function: Test RegisterFoldStatusListener & UnRegisterFoldStatusListener in class HCameraService
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: After executing RegisterFoldStatusListener,isFoldRegister will be changed to true,
 *                  after executing UnRegisterFoldStatusListener,isFoldRegister will be changed to false
 */
HWTEST_F(HCameraServiceUnit, HCamera_service_unittest_007, TestSize.Level0)
{
    cameraService_->RegisterFoldStatusListener();
    EXPECT_TRUE(cameraService_->isFoldRegister);
    cameraService_->UnRegisterFoldStatusListener();
    EXPECT_FALSE(cameraService_->isFoldRegister);
}

/*
 * Feature: CameraService
 * Function: Test AllowOpenByOHSide in class HCameraService
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test AllowOpenByOHSide,after executing AllowOpenByOHSide,the argument canOpenCamera
 *                  will be changed from false to true
 */
HWTEST_F(HCameraServiceUnit, HCamera_service_unittest_008, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_FALSE(cameras.empty());
    std::string cameraId = cameras[0]->GetID();
    int32_t state = 0;
    bool canOpenCamera = false;
    int32_t ret = cameraService_->AllowOpenByOHSide(cameraId, state, canOpenCamera);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_TRUE(canOpenCamera);
}

/*
 * Feature: CameraService
 * Function: Test SetPeerCallback with callback as nullptr in class HCameraService
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetPeerCallback with callback as nullptr,returns CAMERA_INVALID_ARG
 */
HWTEST_F(HCameraServiceUnit, HCamera_service_unittest_009, TestSize.Level0)
{
    sptr<ICameraBroker> callback = nullptr;
    int32_t ret = cameraService_->SetPeerCallback(callback);
    EXPECT_EQ(ret, CAMERA_INVALID_ARG);
}

/*
 * Feature: CameraService
 * Function: Test UnsetPeerCallback in class HCameraService
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Unset the Callback to default value,returns CAMERA_OK
 */
HWTEST_F(HCameraServiceUnit, HCamera_service_unittest_010, TestSize.Level0)
{
    int32_t ret = cameraService_->UnsetPeerCallback();
    EXPECT_EQ(ret, CAMERA_OK);
}

/*
 * Feature: CameraService
 * Function: Test DumpCameraSummary in class HCameraService
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: After executing DumpCameraSummary, the argument infoDumper will be changed,
 *                  "Number of Camera clients" can be found in dumperString_
 */
HWTEST_F(HCameraServiceUnit, HCamera_service_unittest_011, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_FALSE(cameras.empty());
    std::vector<string> cameraIds;
    for (auto camera : cameras) {
        std::string cameraId = camera->GetID();
        cameraIds.push_back(cameraId);
    }
    EXPECT_NE(cameraIds.size(), 0);
    CameraInfoDumper infoDumper(0);
    cameraService_->DumpCameraSummary(cameraIds, infoDumper);
    std::string msgString = infoDumper.dumperString_;
    auto ret = [msgString]()->bool {
        return (msgString.find("Number of Camera clients") != std::string::npos);
    }();
    EXPECT_TRUE(ret);
}

/*
 * Feature: CameraService
 * Function: Test DumpCameraAbility in class HCameraService
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test DumpCameraAbility
 */
HWTEST_F(HCameraServiceUnit, HCamera_service_unittest_012, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_FALSE(cameras.empty());
    cameraHostManager_->Init();
    std::string cameraId = cameras[0]->GetID();
    shared_ptr<OHOS::Camera::CameraMetadata> cameraAbility =
        std::make_shared<OHOS::Camera::CameraMetadata>(METADATA_ITEM_SIZE, METADATA_DATA_SIZE);
    int32_t cameraPosition = 16;
    cameraAbility->addEntry(OHOS_ABILITY_CAMERA_POSITION, &cameraPosition, sizeof(int32_t));
    uint8_t type = 16;
    cameraAbility->addEntry(OHOS_ABILITY_CAMERA_TYPE, &type, sizeof(uint8_t));
    uint8_t value_u8 = 16;
    cameraAbility->addEntry(OHOS_ABILITY_CAMERA_CONNECTION_TYPE, &value_u8, sizeof(uint8_t));
    common_metadata_header_t* metadataEntry = cameraAbility->get();
    CameraInfoDumper infoDumper(0);
    cameraService_->DumpCameraAbility(metadataEntry, infoDumper);
    std::string msgString = infoDumper.dumperString_;
    bool ret = [msgString]()->bool {
        return (msgString.find("Camera Position") != std::string::npos);
    }();
    EXPECT_FALSE(ret);
    ret = [msgString]()->bool {
        return (msgString.find("Camera Type") != std::string::npos);
    }();
    EXPECT_FALSE(ret);
    ret = [msgString]()->bool {
        return (msgString.find("Camera Connection Type") != std::string::npos);
    }();
    EXPECT_FALSE(ret);
}

/*
 * Feature: CameraService
 * Function: Test DumpCameraStreamInfo in class HCameraService
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test DumpCameraStreamInfo when there is no data for
 *     OHOS_ABILITY_STREAM_AVAILABLE_BASIC_CONFIGURATIONS
 */
HWTEST_F(HCameraServiceUnit, HCamera_service_unittest_013, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_FALSE(cameras.empty());

    cameraHostManager_->Init();
    std::string cameraId = cameras[0]->GetID();
    shared_ptr<OHOS::Camera::CameraMetadata> cameraAbility = cameras[0]->GetMetadata();
    cameraHostManager_->GetCameraAbility(cameraId, cameraAbility);
    common_metadata_header_t* metadataEntry = cameraAbility->get();
    OHOS::Camera::DeleteCameraMetadataItem(metadataEntry, OHOS_ABILITY_STREAM_AVAILABLE_BASIC_CONFIGURATIONS);
    CameraInfoDumper infoDumper(0);
    cameraService_->DumpCameraStreamInfo(metadataEntry, infoDumper);
    std::string msgString = infoDumper.dumperString_;
    bool ret = [msgString]()->bool {
        return (msgString.find("Basic Stream Info Size") != std::string::npos);
    }();
    EXPECT_FALSE(ret);
    ret = [msgString]()->bool {
        return (msgString.find("Format:[") != std::string::npos);
    }();
    EXPECT_FALSE(ret);
}

/*
 * Feature: CameraService
 * Function: Test DumpCameraZoom in class HCameraService
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test DumpCameraZoom
 */
HWTEST_F(HCameraServiceUnit, HCamera_service_unittest_014, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_FALSE(cameras.empty());
    cameraHostManager_->Init();
    std::string cameraId = cameras[0]->GetID();
    shared_ptr<OHOS::Camera::CameraMetadata> cameraAbility =
        std::make_shared<OHOS::Camera::CameraMetadata>(METADATA_ITEM_SIZE, METADATA_DATA_SIZE);

    int32_t zoomCap[3] = {0, 10, 16};
    cameraAbility->addEntry(OHOS_ABILITY_ZOOM_CAP, &zoomCap, sizeof(zoomCap) / sizeof(zoomCap[0]));

    int32_t sceneZoomCap[3] = {1, 10, 16};
    cameraAbility->addEntry(OHOS_ABILITY_SCENE_ZOOM_CAP, &sceneZoomCap, sizeof(zoomCap) / sizeof(zoomCap[0]));

    float value_f[2] = {1.0, 2.0};
    cameraAbility->addEntry(OHOS_ABILITY_ZOOM_RATIO_RANGE, &value_f, sizeof(value_f) / sizeof(value_f[0]));
    common_metadata_header_t* metadataEntry = cameraAbility->get();
    CameraInfoDumper infoDumper(0);
    cameraService_->DumpCameraZoom(metadataEntry, infoDumper);
    std::string msgString = infoDumper.dumperString_;
    bool ret = [msgString]()->bool {
        return (msgString.find("OHOS_ABILITY_ZOOM_CAP data size") != std::string::npos);
    }();
    EXPECT_TRUE(ret);
    ret = [msgString]()->bool {
        return (msgString.find("OHOS_ABILITY_SCENE_ZOOM_CAP data size") != std::string::npos);
    }();
    EXPECT_TRUE(ret);
    ret = [msgString]()->bool {
        return (msgString.find("OHOS_ABILITY_ZOOM_RATIO_RANGE data size") != std::string::npos);
    }();
    EXPECT_TRUE(ret);
}

/*
 * Feature: CameraService
 * Function: Test OnAddSystemAbility in class HCameraService
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test OnAddSystemAbility with different systemAbilityId
 */
HWTEST_F(HCameraServiceUnit, HCamera_service_unittest_015, TestSize.Level0)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    sptr<ICameraDeviceService> device = nullptr;
    cameraService_->CreateCameraDevice(cameraIds[0], device);
    ASSERT_NE(device, nullptr);
    device->Open();

    std::string deviceId = "";
    cameraService_->OnAddSystemAbility(0, deviceId);
    EXPECT_EQ(deviceId, "");

    cameraService_->OnRemoveSystemAbility(0, deviceId);
    EXPECT_EQ(deviceId, "");

    cameraService_->OnRemoveSystemAbility(DISTRIBUTED_KV_DATA_SERVICE_ABILITY_ID, deviceId);
    EXPECT_EQ(deviceId, "");

    device->Release();
    device->Close();
}

/*
 * Feature: CameraService
 * Function: Test GetCameras in class HCameraService
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetCameras when isFoldable and isFoldableInit are false
 */
HWTEST_F(HCameraServiceUnit, HCamera_service_unittest_016, TestSize.Level0)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    sptr<ICameraDeviceService> device = nullptr;
    cameraService_->CreateCameraDevice(cameraIds[0], device);
    ASSERT_NE(device, nullptr);
    device->Open();

    cameraService_->isFoldable = false;
    cameraService_->isFoldableInit = false;
    vector<shared_ptr<OHOS::Camera::CameraMetadata>> cameraAbilityList;
    int32_t ret = cameraService_->GetCameras(cameraIds, cameraAbilityList);
    EXPECT_EQ(ret, CAMERA_OK);

    device->Release();
    device->Close();
}

/*
 * Feature: CameraService
 * Function: Test GetCameraMetaInfo in class HCameraService
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetCameraMetaInfo with different isFoldable cameraPosition and foldType
 */
HWTEST_F(HCameraServiceUnit, HCamera_service_unittest_017, TestSize.Level0)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    sptr<ICameraDeviceService> device = nullptr;
    cameraService_->CreateCameraDevice(cameraIds[0], device);
    ASSERT_NE(device, nullptr);
    device->Open();

    shared_ptr<OHOS::Camera::CameraMetadata> cameraAbility =
        std::make_shared<OHOS::Camera::CameraMetadata>(METADATA_ITEM_SIZE, METADATA_DATA_SIZE);
    int32_t cameraPosition = OHOS_CAMERA_POSITION_FRONT;
    cameraAbility->addEntry(OHOS_ABILITY_CAMERA_POSITION, &cameraPosition, sizeof(int32_t));
    int32_t foldType = OHOS_CAMERA_POSITION_OTHER;
    cameraAbility->addEntry(OHOS_ABILITY_CAMERA_FOLDSCREEN_TYPE, &foldType, sizeof(int32_t));
    cameraService_->isFoldable = true;
    shared_ptr<CameraMetaInfo> ret = cameraService_->GetCameraMetaInfo(cameraIds[0], cameraAbility);
    EXPECT_NE(ret, nullptr);

    cameraService_->isFoldable = false;
    ret = cameraService_->GetCameraMetaInfo(cameraIds[0], cameraAbility);
    EXPECT_NE(ret, nullptr);

    cameraPosition = 0;
    cameraAbility->updateEntry(OHOS_ABILITY_CAMERA_POSITION, &cameraPosition, 1);
    ret = cameraService_->GetCameraMetaInfo(cameraIds[0], cameraAbility);
    EXPECT_NE(ret, nullptr);

    foldType = 0;
    cameraAbility->updateEntry(OHOS_ABILITY_CAMERA_FOLDSCREEN_TYPE, &foldType, 1);
    ret = cameraService_->GetCameraMetaInfo(cameraIds[0], cameraAbility);
    EXPECT_NE(ret, nullptr);

    cameraService_->isFoldable = true;
    cameraPosition = OHOS_CAMERA_POSITION_FRONT;
    cameraAbility->updateEntry(OHOS_ABILITY_CAMERA_POSITION, &cameraPosition, 1);
    ret = cameraService_->GetCameraMetaInfo(cameraIds[0], cameraAbility);
    EXPECT_NE(ret, nullptr);

    cameraPosition = 0;
    cameraAbility->updateEntry(OHOS_ABILITY_CAMERA_POSITION, &cameraPosition, 1);
    foldType = OHOS_CAMERA_POSITION_OTHER;
    cameraAbility->updateEntry(OHOS_ABILITY_CAMERA_FOLDSCREEN_TYPE, &foldType, 1);
    ret = cameraService_->GetCameraMetaInfo(cameraIds[0], cameraAbility);
    EXPECT_NE(ret, nullptr);

    device->Release();
    device->Close();
}

/*
 * Feature: CameraService
 * Function: Test GetCameraMetaInfo in class HCameraService
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetCameraMetaInfo with different isFoldable cameraPosition and foldType
 */
HWTEST_F(HCameraServiceUnit, HCamera_service_unittest_018, TestSize.Level0)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    sptr<ICameraDeviceService> device = nullptr;
    cameraService_->CreateCameraDevice(cameraIds[0], device);
    ASSERT_NE(device, nullptr);
    device->Open();

    shared_ptr<OHOS::Camera::CameraMetadata> cameraAbility =
        std::make_shared<OHOS::Camera::CameraMetadata>(METADATA_ITEM_SIZE, METADATA_DATA_SIZE);
    int32_t cameraPosition = OHOS_CAMERA_POSITION_FRONT;
    cameraAbility->addEntry(OHOS_ABILITY_CAMERA_POSITION, &cameraPosition, sizeof(int32_t));
    int32_t foldType = OHOS_CAMERA_FOLDSCREEN_INNER;
    cameraAbility->addEntry(OHOS_ABILITY_CAMERA_FOLDSCREEN_TYPE, &foldType, sizeof(int32_t));
    cameraService_->isFoldable = true;
    shared_ptr<CameraMetaInfo> ret = cameraService_->GetCameraMetaInfo(cameraIds[0], cameraAbility);
    EXPECT_NE(ret, nullptr);

    cameraService_->isFoldable = false;
    ret = cameraService_->GetCameraMetaInfo(cameraIds[0], cameraAbility);
    EXPECT_NE(ret, nullptr);

    cameraPosition = 0;
    cameraAbility->updateEntry(OHOS_ABILITY_CAMERA_POSITION, &cameraPosition, 1);
    ret = cameraService_->GetCameraMetaInfo(cameraIds[0], cameraAbility);
    EXPECT_NE(ret, nullptr);

    foldType = 0;
    cameraAbility->updateEntry(OHOS_ABILITY_CAMERA_FOLDSCREEN_TYPE, &foldType, 1);
    ret = cameraService_->GetCameraMetaInfo(cameraIds[0], cameraAbility);
    EXPECT_NE(ret, nullptr);

    cameraService_->isFoldable = true;
    cameraPosition = OHOS_CAMERA_POSITION_FRONT;
    cameraAbility->updateEntry(OHOS_ABILITY_CAMERA_POSITION, &cameraPosition, 1);
    ret = cameraService_->GetCameraMetaInfo(cameraIds[0], cameraAbility);
    EXPECT_NE(ret, nullptr);

    cameraPosition = 0;
    cameraAbility->updateEntry(OHOS_ABILITY_CAMERA_POSITION, &cameraPosition, 1);
    foldType = OHOS_CAMERA_FOLDSCREEN_INNER;
    cameraAbility->updateEntry(OHOS_ABILITY_CAMERA_FOLDSCREEN_TYPE, &foldType, 1);
    ret = cameraService_->GetCameraMetaInfo(cameraIds[0], cameraAbility);
    EXPECT_NE(ret, nullptr);

    device->Release();
    device->Close();
}

/*
 * Feature: CameraService
 * Function: Test OnCameraStatus in class HCameraService
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test OnCameraStatus with different cameraServiceCallbacks_
 */
HWTEST_F(HCameraServiceUnit, HCamera_service_unittest_019, TestSize.Level0)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    sptr<ICameraDeviceService> device = nullptr;
    cameraService_->CreateCameraDevice(cameraIds[0], device);
    ASSERT_NE(device, nullptr);
    device->Open();

    cameraService_->cameraServiceCallbacks_ = {};
    cameraService_->cameraStatusCallbacks_ = {};
    cameraService_->OnCameraStatus(cameraIds[0], CameraStatus::CAMERA_STATUS_AVAILABLE, CallbackInvoker::APPLICATION);
    EXPECT_TRUE(cameraService_->cameraStatusCallbacks_.empty());
    EXPECT_EQ(cameraService_->UnSetCameraCallback(IPCSkeleton::GetCallingPid()), CAMERA_OK);

    sptr<ICameraServiceCallbackTest> callback = new ICameraServiceCallbackTest();
    cameraService_->cameraServiceCallbacks_ = {{1, callback}, {2, nullptr}};
    cameraService_->OnCameraStatus(cameraIds[0], CameraStatus::CAMERA_STATUS_AVAILABLE, CallbackInvoker::APPLICATION);
    EXPECT_EQ(cameraService_->cameraStatusCallbacks_.size(), 1);

    if (callback) {
        callback = nullptr;
    }
    device->Release();
    device->Close();
}

/*
 * Feature: CameraService
 * Function: Test OnFlashlightStatus in class HCameraService
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test OnFlashlightStatus with different cameraServiceCallbacks_
 */
HWTEST_F(HCameraServiceUnit, HCamera_service_unittest_020, TestSize.Level0)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    sptr<ICameraDeviceService> device = nullptr;
    cameraService_->CreateCameraDevice(cameraIds[0], device);
    ASSERT_NE(device, nullptr);
    device->Open();

    cameraService_->cameraServiceCallbacks_ = {};
    cameraService_->OnFlashlightStatus(cameraIds[0], FlashStatus::FLASH_STATUS_OFF);
    EXPECT_TRUE(cameraService_->cameraServiceCallbacks_.empty());

    sptr<ICameraServiceCallbackTest> callback = new ICameraServiceCallbackTest();
    cameraService_->cameraServiceCallbacks_ = {{1, callback}, {2, nullptr}};
    cameraService_->OnFlashlightStatus(cameraIds[0], FlashStatus::FLASH_STATUS_OFF);
    EXPECT_EQ(cameraService_->cameraServiceCallbacks_.size(), 2);

    if (callback) {
        callback = nullptr;
    }
    device->Release();
    device->Close();
}

/*
 * Feature: CameraService
 * Function: Test OnMute in class HCameraService
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test OnMute with cameraServiceCallbacks_ is different and peerCallback_ is not null;
 */
HWTEST_F(HCameraServiceUnit, HCamera_service_unittest_021, TestSize.Level0)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    sptr<ICameraDeviceService> device = nullptr;
    cameraService_->CreateCameraDevice(cameraIds[0], device);
    ASSERT_NE(device, nullptr);
    device->Open();

    cameraService_->cameraMuteServiceCallbacks_ = {};
    cameraService_->peerCallback_ = new ICameraBrokerTest();
    cameraService_->OnMute(true);
    EXPECT_TRUE(cameraService_->cameraMuteServiceCallbacks_.empty());
    EXPECT_EQ(cameraService_->UnSetMuteCallback(IPCSkeleton::GetCallingPid()), CAMERA_OK);

    sptr<ICameraMuteServiceCallbackTest> callback = new ICameraMuteServiceCallbackTest();
    cameraService_->cameraMuteServiceCallbacks_ = {{1, callback}, {2, nullptr}};
    cameraService_->OnMute(true);
    EXPECT_EQ(cameraService_->cameraMuteServiceCallbacks_.size(), 2);

    if (cameraService_->peerCallback_) {
        cameraService_->peerCallback_ = nullptr;
    }
    if (callback) {
        callback = nullptr;
    }
    device->Release();
    device->Close();
}

/*
 * Feature: CameraService
 * Function: Test CreateDefaultSettingForRestore in class HCameraService
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CreateDefaultSettingForRestore with correct currentSetting
 */
HWTEST_F(HCameraServiceUnit, HCamera_service_unittest_022, TestSize.Level0)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    sptr<ICameraDeviceService> device = nullptr;
    cameraService_->CreateCameraDevice(cameraIds[0], device);
    ASSERT_NE(device, nullptr);
    device->Open();

    uint32_t callingTokenId = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> activeDevice = new HCameraDevice(cameraHostManager_, cameraIds[0], callingTokenId);
    std::shared_ptr<OHOS::Camera::CameraMetadata> cachedSettings =
        std::make_shared<OHOS::Camera::CameraMetadata>(METADATA_ITEM_SIZE, METADATA_DATA_SIZE);
    std::vector<int32_t> fpsRange = {METADATA_ITEM_SIZE, METADATA_DATA_SIZE};
    cachedSettings->addEntry(OHOS_CONTROL_FPS_RANGES, fpsRange.data(), fpsRange.size());
    int32_t userId = 0;
    cachedSettings->addEntry(OHOS_CAMERA_USER_ID, &userId, 1);
    int32_t effectControl[2] = {0, 1};
    cachedSettings->addEntry(OHOS_CONTROL_PORTRAIT_EFFECT_TYPE, &effectControl,
        sizeof(effectControl) / sizeof(effectControl[0]));
    activeDevice->cachedSettings_ = cachedSettings;

    std::shared_ptr<OHOS::Camera::CameraMetadata> ret = cameraService_->CreateDefaultSettingForRestore(activeDevice);
    EXPECT_NE(ret, nullptr);

    if (activeDevice) {
        activeDevice = nullptr;
    }
    device->Release();
    device->Close();
}

/*
 * Feature: CameraService
 * Function: Test OnTorchStatus in class HCameraService
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test OnTorchStatus with different torchServiceCallbacks_
 */
HWTEST_F(HCameraServiceUnit, HCamera_service_unittest_023, TestSize.Level0)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    sptr<ICameraDeviceService> device = nullptr;
    cameraService_->CreateCameraDevice(cameraIds[0], device);
    ASSERT_NE(device, nullptr);
    device->Open();

    cameraService_->torchServiceCallbacks_ = {};
    cameraService_->OnTorchStatus(TorchStatus::TORCH_STATUS_OFF);
    EXPECT_TRUE(cameraService_->torchServiceCallbacks_.empty());

    sptr<ITorchServiceCallbackTest> callback = new ITorchServiceCallbackTest();
    cameraService_->torchServiceCallbacks_ = {{1, callback}, {2, nullptr}};
    cameraService_->OnTorchStatus(TorchStatus::TORCH_STATUS_OFF);
    EXPECT_EQ(cameraService_->torchServiceCallbacks_.size(), 2);

    if (callback) {
        callback = nullptr;
    }
    device->Release();
    device->Close();
}

/*
 * Feature: CameraService
 * Function: Test OnFoldStatusChanged in class HCameraService
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test OnFoldStatusChanged with different curFoldStatus preFoldStatus_ and foldServiceCallbacks_
 */
HWTEST_F(HCameraServiceUnit, HCamera_service_unittest_024, TestSize.Level0)
{
    OHOS::Rosen::FoldStatus foldStatus = OHOS::Rosen::FoldStatus::HALF_FOLD;
    cameraService_->preFoldStatus_ = FoldStatus::FOLDED;
    cameraService_->foldServiceCallbacks_ = {};
    cameraService_->OnFoldStatusChanged(foldStatus);
    EXPECT_EQ(cameraService_->preFoldStatus_, FoldStatus::HALF_FOLD);
    EXPECT_TRUE(cameraService_->foldServiceCallbacks_.empty());

    foldStatus = OHOS::Rosen::FoldStatus::EXPAND;
    cameraService_->preFoldStatus_ = FoldStatus::FOLDED;
    sptr<IFoldServiceCallbackTest> callback = new IFoldServiceCallbackTest();
    cameraService_->foldServiceCallbacks_ = {{1, callback}, {2, nullptr}};
    cameraService_->OnFoldStatusChanged(foldStatus);
    EXPECT_EQ(cameraService_->preFoldStatus_, FoldStatus::EXPAND);
    EXPECT_EQ(cameraService_->foldServiceCallbacks_.size(), 2);

    if (callback) {
        callback = nullptr;
    }
}

/*
 * Feature: CameraService
 * Function: Test SetFoldStatusCallback in class HCameraService
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetFoldStatusCallback when isInnerCallback is true
 */
HWTEST_F(HCameraServiceUnit, HCamera_service_unittest_025, TestSize.Level0)
{
    sptr<IFoldServiceCallback> callback = new IFoldServiceCallbackTest();
    EXPECT_EQ(cameraService_->SetFoldStatusCallback(callback, true), CAMERA_OK);

    pid_t pid = IPCSkeleton::GetCallingPid();
    cameraService_->foldServiceCallbacks_ = {{pid, nullptr}};
    EXPECT_EQ(cameraService_->UnSetFoldStatusCallback(pid), CAMERA_OK);

    pid = IPCSkeleton::GetCallingPid();
    pid_t pid_1 = 1;
    if (pid_1 == pid) {
        pid_1++;
    }
    cameraService_->foldServiceCallbacks_ = {{pid_1, nullptr}};
    EXPECT_EQ(cameraService_->UnSetFoldStatusCallback(pid), CAMERA_OK);

    pid = IPCSkeleton::GetCallingPid();
    pid_1 = 1;
    if (pid_1 == pid) {
        pid_1++;
    }
    cameraService_->foldServiceCallbacks_ = {{pid_1, callback}};
    EXPECT_EQ(cameraService_->UnSetFoldStatusCallback(pid), CAMERA_OK);

    if (callback) {
        callback = nullptr;
    }
}

/*
 * Feature: CameraService
 * Function: Test MuteCameraFunc in class HCameraService
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test MuteCameraFunc when HCameraDeviceHolder is nullptr or not nullptr
 */
HWTEST_F(HCameraServiceUnit, HCamera_service_unittest_026, TestSize.Level0)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    sptr<ICameraDeviceService> device = nullptr;
    cameraService_->CreateCameraDevice(cameraIds[0], device);
    ASSERT_NE(device, nullptr);
    device->Open();

    cameraHostManager_->AddCameraHost(LOCAL_SERVICE_NAME);
    shared_ptr<OHOS::Camera::CameraMetadata> cameraAbility =
        std::make_shared<OHOS::Camera::CameraMetadata>(METADATA_ITEM_SIZE, METADATA_DATA_SIZE);;
    cameraHostManager_->GetCameraAbility(cameraIds[0], cameraAbility);
    uint8_t value_u8 = static_cast<uint8_t>(OHOS_CAMERA_MUTE_MODE_SOLID_COLOR_BLACK);
    cameraAbility->addEntry(OHOS_ABILITY_MUTE_MODES, &value_u8, sizeof(uint8_t));

    sptr<HCameraDeviceManager> deviceManager = HCameraDeviceManager::GetInstance();
    uint32_t callingTokenId = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> camDevice = new HCameraDevice(cameraHostManager_, cameraIds[0], callingTokenId);
    int32_t cost = 0;
    std::set<std::string> conflicting;
    camDevice->GetCameraResourceCost(cost, conflicting);
    int32_t uidOfRequestProcess = IPCSkeleton::GetCallingUid();
    int32_t pidOfRequestProcess = IPCSkeleton::GetCallingPid();
    uint32_t accessTokenIdOfRequestProc = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDeviceHolder> cameraHolder = new HCameraDeviceHolder(
        pidOfRequestProcess, uidOfRequestProcess, 0,
        1, camDevice, accessTokenIdOfRequestProc, cost, conflicting);
    sptr<HCameraDeviceHolder> cameraHolder_1 = new HCameraDeviceHolder(
        pidOfRequestProcess, uidOfRequestProcess, 0,
        1, camDevice, accessTokenIdOfRequestProc, cost, conflicting);
    cameraHolder_1->device_ = nullptr;
    deviceManager->activeCameras_.push_back(cameraHolder_1);
    deviceManager->activeCameras_.push_back(cameraHolder);
    cameraService_->cameraDataShareHelper_ = nullptr;
    EXPECT_EQ(cameraService_->MuteCameraFunc(true), CAMERA_ALLOC_ERROR);

    if (camDevice) {
        camDevice = nullptr;
    }
    if (cameraHolder) {
        cameraHolder = nullptr;
    }
    if (cameraHolder_1) {
        cameraHolder_1 = nullptr;
    }
    device->Release();
    device->Close();
}

/*
 * Feature: CameraService
 * Function: Test PrelaunchCamera in class HCameraService
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test PrelaunchCamera when preCameraId_ is null or is not null
 */
HWTEST_F(HCameraServiceUnit, HCamera_service_unittest_027, TestSize.Level0)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    sptr<ICameraDeviceService> device = nullptr;
    cameraService_->CreateCameraDevice(cameraIds[0], device);
    ASSERT_NE(device, nullptr);
    device->Open();

    HCameraDeviceManager::GetInstance()->stateOfACamera_.Clear();
    cameraService_->preCameraId_ = cameraIds[0];
    EXPECT_EQ(cameraService_->PrelaunchCamera(), CAMERA_OK);

    HCameraDeviceManager::GetInstance()->stateOfACamera_.Clear();
    cameraIds[0].resize(0);
    cameraService_->preCameraId_.clear();
    EXPECT_EQ(cameraService_->PrelaunchCamera(), 0);
    EXPECT_EQ(cameraService_->PreSwitchCamera(cameraIds[0]), CAMERA_INVALID_ARG);
    device->Release();
    device->Close();
}

/*
 * Feature: CameraService
 * Function: Test AllowOpenByOHSide in class HCameraService
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test AllowOpenByOHSide when activedevice is not null or is null
 */
HWTEST_F(HCameraServiceUnit, HCamera_service_unittest_028, TestSize.Level0)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    sptr<ICameraDeviceService> device = nullptr;
    cameraService_->CreateCameraDevice(cameraIds[0], device);
    ASSERT_NE(device, nullptr);
    device->Open();
    int32_t state = 0;
    bool canOpenCamera = false;

    sptr<HCameraDeviceManager> deviceManager = HCameraDeviceManager::GetInstance();
    uint32_t callingTokenId = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> camDevice = new HCameraDevice(cameraHostManager_, cameraIds[0], callingTokenId);
    int32_t cost = 0;
    std::set<std::string> conflicting;
    camDevice->GetCameraResourceCost(cost, conflicting);
    int32_t uidOfRequestProcess = IPCSkeleton::GetCallingUid();
    int32_t pidOfRequestProcess = IPCSkeleton::GetCallingPid();
    uint32_t accessTokenIdOfRequestProc = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDeviceHolder> cameraHolder = new HCameraDeviceHolder(
        pidOfRequestProcess, uidOfRequestProcess, 0,
        1, camDevice, accessTokenIdOfRequestProc, cost, conflicting);
    deviceManager->pidToCameras_.EnsureInsert(pidOfRequestProcess, cameraHolder);
    int32_t ret = cameraService_->AllowOpenByOHSide(cameraIds[0], state, canOpenCamera);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_TRUE(canOpenCamera);

    canOpenCamera = false;
    deviceManager->pidToCameras_.Clear();
    cameraHolder->device_ = nullptr;
    deviceManager->pidToCameras_.EnsureInsert(pidOfRequestProcess, cameraHolder);
    ret = cameraService_->AllowOpenByOHSide(cameraIds[0], state, canOpenCamera);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_FALSE(canOpenCamera);

    if (camDevice) {
        camDevice = nullptr;
    }
    if (cameraHolder) {
        cameraHolder = nullptr;
    }
}

/*
 * Feature: CameraService
 * Function: Test AllowOpenByOHSide in class HCameraService
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test AllowOpenByOHSide when activedevice is not null or is null
 */
HWTEST_F(HCameraServiceUnit, HCamera_service_unittest_029, TestSize.Level0)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    sptr<ICameraDeviceService> device = nullptr;
    cameraService_->CreateCameraDevice(cameraIds[0], device);
    ASSERT_NE(device, nullptr);
    device->Open();

    shared_ptr<OHOS::Camera::CameraMetadata> cameraAbility =
        std::make_shared<OHOS::Camera::CameraMetadata>(METADATA_ITEM_SIZE, METADATA_DATA_SIZE);;
    cameraHostManager_->GetCameraAbility(cameraIds[0], cameraAbility);
    common_metadata_header_t* metadata = cameraAbility->get();
    OHOS::Camera::DeleteCameraMetadataItem(metadata, OHOS_ABILITY_PRELAUNCH_AVAILABLE);
    EXPECT_FALSE(cameraService_->IsPrelaunchSupported(cameraIds[0]));
    device->Release();
    device->Close();
}

/*
 * Feature: CameraService
 * Function: Test DumpCameraFlash in class HCameraService
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: After executing DumpCameraFlash, the argument infoDumper will be changed,
 *                  "Available Focus Modes:[" can be found in dumperString_
 */
HWTEST_F(HCameraServiceUnit, HCamera_service_unittest_030, TestSize.Level0)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    sptr<ICameraDeviceService> device = nullptr;
    cameraService_->CreateCameraDevice(cameraIds[0], device);
    ASSERT_NE(device, nullptr);
    device->Open();

    shared_ptr<OHOS::Camera::CameraMetadata> cameraAbility =
        std::make_shared<OHOS::Camera::CameraMetadata>(METADATA_ITEM_SIZE, METADATA_DATA_SIZE);
    common_metadata_header_t* metadataEntry = cameraAbility->get();
    uint8_t cameraFocusMode = 16;
    cameraAbility->addEntry(OHOS_ABILITY_FLASH_MODES, &cameraFocusMode, sizeof(uint8_t));
    CameraInfoDumper infoDumper(0);
    cameraService_->DumpCameraFlash(metadataEntry, infoDumper);
    std::string msgString = infoDumper.dumperString_;
    auto ret = [msgString]()->bool {
        return (msgString.find("Available Flash Modes:[") != std::string::npos);
    }();
    EXPECT_TRUE(ret);
    device->Release();
    device->Close();
}

/*
 * Feature: CameraService
 * Function: Test DumpCameraAF in class HCameraService
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: After executing DumpCameraAF, the argument infoDumper will be changed,
 *                  "Available Focus Modes:[" can be found in dumperString_
 */
HWTEST_F(HCameraServiceUnit, HCamera_service_unittest_031, TestSize.Level0)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    sptr<ICameraDeviceService> device = nullptr;
    cameraService_->CreateCameraDevice(cameraIds[0], device);
    ASSERT_NE(device, nullptr);
    device->Open();

    shared_ptr<OHOS::Camera::CameraMetadata> cameraAbility =
        std::make_shared<OHOS::Camera::CameraMetadata>(METADATA_ITEM_SIZE, METADATA_DATA_SIZE);
    common_metadata_header_t* metadataEntry = cameraAbility->get();
    uint8_t cameraFocusMode = 16;
    cameraAbility->addEntry(OHOS_ABILITY_FOCUS_MODES, &cameraFocusMode, sizeof(uint8_t));
    CameraInfoDumper infoDumper(0);
    cameraService_->DumpCameraAF(metadataEntry, infoDumper);
    std::string msgString = infoDumper.dumperString_;
    auto ret = [msgString]()->bool {
        return (msgString.find("Available Focus Modes:[") != std::string::npos);
    }();
    EXPECT_TRUE(ret);
    device->Release();
    device->Close();
}

/*
 * Feature: CameraService
 * Function: Test DumpCameraAE in class HCameraService
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: After executing DumpCameraAE, the argument infoDumper will be changed,
 *                  "Available Exposure Modes:[ " can be found in dumperString_
 */
HWTEST_F(HCameraServiceUnit, HCamera_service_unittest_032, TestSize.Level0)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    sptr<ICameraDeviceService> device = nullptr;
    cameraService_->CreateCameraDevice(cameraIds[0], device);
    ASSERT_NE(device, nullptr);
    device->Open();

    shared_ptr<OHOS::Camera::CameraMetadata> cameraAbility =
        std::make_shared<OHOS::Camera::CameraMetadata>(METADATA_ITEM_SIZE, METADATA_DATA_SIZE);
    common_metadata_header_t* metadataEntry = cameraAbility->get();
    uint8_t cameraExposureMode = 16;
    cameraAbility->addEntry(OHOS_ABILITY_EXPOSURE_MODES, &cameraExposureMode, sizeof(uint8_t));
    CameraInfoDumper infoDumper(0);
    cameraService_->DumpCameraAE(metadataEntry, infoDumper);
    std::string msgString = infoDumper.dumperString_;
    auto ret = [msgString]()->bool {
        return (msgString.find("Available Exposure Modes:[") != std::string::npos);
    }();
    EXPECT_TRUE(ret);
    device->Release();
    device->Close();
}

/*
 * Feature: CameraService
 * Function: Test DumpCameraVideoStabilization in class HCameraService
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: After executing DumpCameraVideoStabilization, the argument infoDumper will be changed,
 *                  "Available Video Stabilization Modes:[" can be found in dumperString_
 */
HWTEST_F(HCameraServiceUnit, HCamera_service_unittest_033, TestSize.Level0)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    sptr<ICameraDeviceService> device = nullptr;
    cameraService_->CreateCameraDevice(cameraIds[0], device);
    ASSERT_NE(device, nullptr);
    device->Open();

    shared_ptr<OHOS::Camera::CameraMetadata> cameraAbility =
        std::make_shared<OHOS::Camera::CameraMetadata>(METADATA_ITEM_SIZE, METADATA_DATA_SIZE);
    common_metadata_header_t* metadataEntry = cameraAbility->get();
    uint8_t cameraVideoStabilizationMode = 16;
    cameraAbility->addEntry(OHOS_ABILITY_VIDEO_STABILIZATION_MODES, &cameraVideoStabilizationMode, sizeof(uint8_t));
    CameraInfoDumper infoDumper(0);
    cameraService_->DumpCameraVideoStabilization(metadataEntry, infoDumper);
    std::string msgString = infoDumper.dumperString_;
    auto ret = [msgString]()->bool {
        return (msgString.find("Available Video Stabilization Modes:[") != std::string::npos);
    }();
    EXPECT_TRUE(ret);
    device->Release();
    device->Close();
}

/*
 * Feature: CameraService
 * Function: Test DumpCameraPrelaunch in class HCameraService
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: After executing DumpCameraPrelaunch, the argument infoDumper will be changed,
 *                  "Available Prelaunch Info:[" can be found in dumperString_
 */
HWTEST_F(HCameraServiceUnit, HCamera_service_unittest_034, TestSize.Level0)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    sptr<ICameraDeviceService> device = nullptr;
    cameraService_->CreateCameraDevice(cameraIds[0], device);
    ASSERT_NE(device, nullptr);
    device->Open();

    shared_ptr<OHOS::Camera::CameraMetadata> cameraAbility =
        std::make_shared<OHOS::Camera::CameraMetadata>(METADATA_ITEM_SIZE, METADATA_DATA_SIZE);
    common_metadata_header_t* metadataEntry = cameraAbility->get();
    uint8_t cameraPrelaunchAvailable = 16;
    cameraAbility->addEntry(OHOS_ABILITY_PRELAUNCH_AVAILABLE, &cameraPrelaunchAvailable, sizeof(uint8_t));
    CameraInfoDumper infoDumper(0);
    cameraService_->DumpCameraPrelaunch(metadataEntry, infoDumper);
    std::string msgString = infoDumper.dumperString_;
    auto ret = [msgString]()->bool {
        return (msgString.find("Available Prelaunch Info:[") != std::string::npos);
    }();
    EXPECT_TRUE(ret);
    device->Release();
    device->Close();
}

/*
 * Feature: CameraService
 * Function: Test DumpCameraThumbnail in class HCameraService
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: After executing DumpCameraThumbnail, the argument infoDumper will be changed,
 *                  "Available Focus Modes:[ " can be found in dumperString_
 */
HWTEST_F(HCameraServiceUnit, HCamera_service_unittest_035, TestSize.Level0)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    sptr<ICameraDeviceService> device = nullptr;
    cameraService_->CreateCameraDevice(cameraIds[0], device);
    ASSERT_NE(device, nullptr);
    device->Open();

    shared_ptr<OHOS::Camera::CameraMetadata> cameraAbility =
        std::make_shared<OHOS::Camera::CameraMetadata>(METADATA_ITEM_SIZE, METADATA_DATA_SIZE);
    common_metadata_header_t* metadataEntry = cameraAbility->get();
    uint8_t cameraQuickThumbnailAvailable = 16;
    cameraAbility->addEntry(OHOS_ABILITY_STREAM_QUICK_THUMBNAIL_AVAILABLE,
        &cameraQuickThumbnailAvailable, sizeof(uint8_t));
    CameraInfoDumper infoDumper(0);
    cameraService_->DumpCameraThumbnail(metadataEntry, infoDumper);
    std::string msgString = infoDumper.dumperString_;
    auto ret = [msgString]()->bool {
        return (msgString.find("Available Thumbnail Info:[") != std::string::npos);
    }();
    EXPECT_TRUE(ret);
    device->Release();
    device->Close();
}

/*
 * Feature: CameraService
 * Function: Test RegisterSensorCallback and UnRegisterSensorCallback in class HCameraService
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test RegisterSensorCallback and UnRegisterSensorCallback in a various order
 */
HWTEST_F(HCameraServiceUnit, HCamera_service_unittest_036, TestSize.Level0)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    sptr<ICameraDeviceService> device = nullptr;
    cameraService_->CreateCameraDevice(cameraIds[0], device);
    ASSERT_NE(device, nullptr);
    device->Open();

    cameraService_->RegisterSensorCallback();
    cameraService_->UnRegisterSensorCallback();
    cameraService_->UnRegisterSensorCallback();
    cameraService_->RegisterSensorCallback();
    EXPECT_NE(cameraService_->user.callback, nullptr);
    device->Release();
    device->Close();
}

/*
 * Feature: CameraService
 * Function: Test UpdateSkinSmoothSetting in class HCameraService
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test UpdateSkinSmoothSetting when changedMetadata can be found
 */
HWTEST_F(HCameraServiceUnit, HCamera_service_unittest_037, TestSize.Level0)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    sptr<ICameraDeviceService> device = nullptr;
    cameraService_->CreateCameraDevice(cameraIds[0], device);
    ASSERT_NE(device, nullptr);
    device->Open();

    shared_ptr<OHOS::Camera::CameraMetadata> changedMetadata =
        std::make_shared<OHOS::Camera::CameraMetadata>(METADATA_ITEM_SIZE, METADATA_DATA_SIZE);
    int skinSmoothValue = 1;
    uint8_t beauty = OHOS_CAMERA_BEAUTY_TYPE_SKIN_SMOOTH;
    changedMetadata->addEntry(OHOS_CONTROL_BEAUTY_TYPE, &beauty, 1);
    changedMetadata->addEntry(OHOS_CONTROL_BEAUTY_SKIN_SMOOTH_VALUE, &skinSmoothValue, 1);
    EXPECT_EQ(cameraService_->UpdateSkinSmoothSetting(changedMetadata, skinSmoothValue), CAMERA_OK);
    device->Release();
    device->Close();
}

/*
 * Feature: CameraService
 * Function: Test UpdateFaceSlenderSetting in class HCameraService
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test UpdateFaceSlenderSetting when changedMetadata can not be found
 */
HWTEST_F(HCameraServiceUnit, HCamera_service_unittest_038, TestSize.Level0)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    sptr<ICameraDeviceService> device = nullptr;
    cameraService_->CreateCameraDevice(cameraIds[0], device);
    ASSERT_NE(device, nullptr);
    device->Open();

    shared_ptr<OHOS::Camera::CameraMetadata> changedMetadata =
        std::make_shared<OHOS::Camera::CameraMetadata>(METADATA_ITEM_SIZE, METADATA_DATA_SIZE);
        common_metadata_header_t* metadataEntry = changedMetadata->get();
    int faceSlenderValue = 1;
    OHOS::Camera::DeleteCameraMetadataItem(metadataEntry, OHOS_CONTROL_BEAUTY_TYPE);
    OHOS::Camera::DeleteCameraMetadataItem(metadataEntry, OHOS_CONTROL_BEAUTY_FACE_SLENDER_VALUE);
    EXPECT_EQ(cameraService_->UpdateFaceSlenderSetting(changedMetadata, faceSlenderValue), CAMERA_OK);
    device->Release();
    device->Close();
}

/*
 * Feature: CameraService
 * Function: Test UpdateSkinToneSetting in class HCameraService
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test UpdateSkinToneSetting when changedMetadata can not be found
 */
HWTEST_F(HCameraServiceUnit, HCamera_service_unittest_039, TestSize.Level0)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    sptr<ICameraDeviceService> device = nullptr;
    cameraService_->CreateCameraDevice(cameraIds[0], device);
    ASSERT_NE(device, nullptr);
    device->Open();

    shared_ptr<OHOS::Camera::CameraMetadata> changedMetadata =
        std::make_shared<OHOS::Camera::CameraMetadata>(METADATA_ITEM_SIZE, METADATA_DATA_SIZE);
        common_metadata_header_t* metadataEntry = changedMetadata->get();
    int skinToneValue = 1;
    OHOS::Camera::DeleteCameraMetadataItem(metadataEntry, OHOS_CONTROL_BEAUTY_TYPE);
    changedMetadata->addEntry(OHOS_CONTROL_BEAUTY_SKIN_TONE_VALUE, &skinToneValue, 1);
    EXPECT_EQ(cameraService_->UpdateSkinToneSetting(changedMetadata, skinToneValue), CAMERA_OK);
    device->Release();
    device->Close();
}

/*
 * Feature: CameraService
 * Function: Test ProxyForFreeze in class HCameraService
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test ProxyForFreeze when isProxy is false and pidList is nulll
 */
HWTEST_F(HCameraServiceUnit, HCamera_service_unittest_040, TestSize.Level0)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    sptr<ICameraDeviceService> device = nullptr;
    cameraService_->CreateCameraDevice(cameraIds[0], device);
    ASSERT_NE(device, nullptr);
    device->Open();

    std::set<int32_t> pidList = {};
    bool isProxy = false;
    EXPECT_EQ(cameraService_->ProxyForFreeze(pidList, isProxy), CAMERA_OK);
    device->Release();
    device->Close();
}

/*
 * Feature: CameraService
 * Function: Test GetCameraOutputStatus in class HCameraService
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetCameraOutputStatus when captureSession is nullptr or is not nullptr
 */
HWTEST_F(HCameraServiceUnit, HCamera_service_unittest_041, TestSize.Level0)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    sptr<ICameraDeviceService> device = nullptr;
    cameraService_->CreateCameraDevice(cameraIds[0], device);
    ASSERT_NE(device, nullptr);
    device->Open();

    pid_t pid = IPCSkeleton::GetCallingPid();
    int32_t status = 1;
    sptr<HCaptureSession> captureSession = nullptr;
    cameraService_->captureSessionsManager_.EnsureInsert(pid, captureSession);
    EXPECT_EQ(cameraService_->GetCameraOutputStatus(pid, status), 0);

    captureSession = new HCaptureSession();
    cameraService_->captureSessionsManager_.Clear();
    cameraService_->captureSessionsManager_.EnsureInsert(pid, captureSession);
    EXPECT_EQ(cameraService_->GetCameraOutputStatus(pid, status), 0);

    if (captureSession != nullptr) {
        captureSession = nullptr;
    }
    device->Release();
    device->Close();
}

/*
 * Feature: CameraService
 * Function: Test OnReceiveEvent in class HCameraService
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test OnReceiveEvent when want.GetAction is "usual.event.CAMERA_STATUS"
 */
HWTEST_F(HCameraServiceUnit, HCamera_service_unittest_042, TestSize.Level0)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    sptr<ICameraDeviceService> device = nullptr;
    cameraService_->CreateCameraDevice(cameraIds[0], device);
    ASSERT_NE(device, nullptr);
    device->Open();

    OHOS::AAFwk::Want want;
    want.SetAction(COMMON_EVENT_CAMERA_STATUS);
    EventFwk::CommonEventData CommonEventData { want };
    cameraService_->OnReceiveEvent(CommonEventData);
    EXPECT_EQ(CommonEventData.GetWant().GetAction(), COMMON_EVENT_CAMERA_STATUS);
    device->Release();
    device->Close();
}

/*
 * Feature: CameraService
 * Function: Test UnSetTorchCallback in class HCameraService
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test UnSetTorchCallback with different cameraServiceCallbacks_
 */
HWTEST_F(HCameraServiceUnit, HCamera_service_unittest_043, TestSize.Level0)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    sptr<ICameraDeviceService> device = nullptr;
    cameraService_->CreateCameraDevice(cameraIds[0], device);
    ASSERT_NE(device, nullptr);
    device->Open();

    cameraService_->torchServiceCallbacks_ = {};
    EXPECT_EQ(cameraService_->UnSetTorchCallback(IPCSkeleton::GetCallingPid()), CAMERA_OK);

    device->Release();
    device->Close();
}

/*
 * Feature: Framework
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test dump with args empty
 */
HWTEST_F(HCameraServiceUnit, HCamera_service_unittest_044, TestSize.Level0)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    sptr<ICameraDeviceService> device = nullptr;
    cameraService_->CreateCameraDevice(cameraIds[0], device);
    ASSERT_NE(device, nullptr);
    device->Open();

    cameraIds = {};
    std::vector<std::shared_ptr<OHOS::Camera::CameraMetadata>> cameraAbilityList = {};
    int32_t ret = cameraService_->GetCameras(cameraIds, cameraAbilityList);

    int fd = 0;
    std::vector<std::u16string> args = {};
    ret = cameraService_->Dump(fd, args);
    EXPECT_EQ(ret, 0);

    device->Release();
    device->Close();
}

/*
 * Feature: Framework
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test HCameraService with anomalous branch
 */
HWTEST_F(HCameraServiceUnit, HCamera_service_unittest_045, TestSize.Level0)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    sptr<ICameraDeviceService> device = nullptr;
    cameraService_->CreateCameraDevice(cameraIds[0], device);
    ASSERT_NE(device, nullptr);
    device->Open();

    sptr<IConsumerSurface> Surface = IConsumerSurface::Create();
    sptr<IBufferProducer> Producer = Surface->GetProducer();

    int32_t height = 0;
    int32_t width = PHOTO_DEFAULT_WIDTH;
    sptr<IStreamRepeat> output = nullptr;
    int32_t intResult = cameraService_->CreateDeferredPreviewOutput(0, width, height, output);
    EXPECT_EQ(intResult, 2);

    width = 0;
    intResult = cameraService_->CreateDeferredPreviewOutput(0, width, height, output);
    EXPECT_EQ(intResult, 2);

    Producer = nullptr;
    intResult = cameraService_->CreatePreviewOutput(Producer, 0, width, height, output);
    EXPECT_EQ(intResult, 2);

    Producer = Surface->GetProducer();
    intResult = cameraService_->CreatePreviewOutput(Producer, 0, width, height, output);
    EXPECT_EQ(intResult, 2);

    width = PREVIEW_DEFAULT_WIDTH;
    intResult = cameraService_->CreatePreviewOutput(Producer, 0, width, height, output);
    EXPECT_EQ(intResult, 2);

    intResult = cameraService_->CreateVideoOutput(Producer, 0, width, height, output);
    EXPECT_EQ(intResult, 2);

    width = 0;
    intResult = cameraService_->CreateVideoOutput(Producer, 0, width, height, output);
    EXPECT_EQ(intResult, 2);

    Producer = nullptr;
    intResult = cameraService_->CreateVideoOutput(Producer, 0, width, height, output);
    EXPECT_EQ(intResult, 2);

    device->Release();
    device->Close();
}

/*
 * Feature: Framework
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test HCameraService with anomalous branch
 */
HWTEST_F(HCameraServiceUnit, HCamera_service_unittest_046, TestSize.Level0)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    sptr<ICameraDeviceService> device = nullptr;
    cameraService_->CreateCameraDevice(cameraIds[0], device);
    ASSERT_NE(device, nullptr);
    device->Open();

    int32_t width = 0;
    int32_t height = 0;

    sptr<IConsumerSurface> Surface = IConsumerSurface::Create();
    sptr<IBufferProducer> Producer = Surface->GetProducer();

    sptr<IStreamCapture> output_1 = nullptr;
    int32_t intResult = cameraService_->CreatePhotoOutput(Producer, 0, width, height, output_1);
    EXPECT_EQ(intResult, 2);

    width = PHOTO_DEFAULT_WIDTH;
    intResult = cameraService_->CreatePhotoOutput(Producer, 0, width, height, output_1);
    EXPECT_EQ(intResult, 2);

    Producer = nullptr;
    intResult = cameraService_->CreatePhotoOutput(Producer, 0, width, height, output_1);
    EXPECT_EQ(intResult, 2);

    sptr<IStreamMetadata> output_2 = nullptr;
    intResult = cameraService_->CreateMetadataOutput(Producer, 0, {1}, output_2);
    EXPECT_EQ(intResult, 2);

    device->Release();
    device->Close();
}

/*
 * Feature: Framework
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test HCameraService with anomalous branch
 */
HWTEST_F(HCameraServiceUnit, HCamera_service_unittest_047, TestSize.Level0)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    sptr<ICameraDeviceService> device = nullptr;
    cameraService_->CreateCameraDevice(cameraIds[0], device);
    ASSERT_NE(device, nullptr);
    device->Open();

    sptr<ICameraServiceCallback> callback = nullptr;
    int32_t intResult = cameraService_->SetCameraCallback(callback);
    EXPECT_EQ(intResult, 2);
    callback = new(std::nothrow) CameraStatusServiceCallback(cameraManager_);
    ASSERT_NE(callback, nullptr);
    intResult = cameraService_->SetCameraCallback(callback);
    EXPECT_EQ(intResult, 0);
    ASSERT_NE(device, nullptr);
    sptr<ICameraMuteServiceCallback> callback_2 = nullptr;
    intResult = cameraService_->SetMuteCallback(callback_2);
    EXPECT_EQ(intResult, 2);

    callback_2 = new(std::nothrow) CameraMuteServiceCallback(cameraManager_);
    ASSERT_NE(callback_2, nullptr);
    intResult = cameraService_->SetMuteCallback(callback_2);
    EXPECT_EQ(intResult, 0);

    shared_ptr<OHOS::Camera::CameraMetadata> cameraAbility;
    int32_t ret = cameraService_->cameraHostManager_->GetCameraAbility(cameraIds[0], cameraAbility);
    ASSERT_EQ(ret, CAMERA_OK);
    ASSERT_NE(cameraAbility, nullptr);

    OHOS::Camera::DeleteCameraMetadataItem(cameraAbility->get(), OHOS_ABILITY_PRELAUNCH_AVAILABLE);

    int activeTime = 15;
    EffectParam effectParam = {0, 0, 0};
    intResult = cameraService_->SetPrelaunchConfig(cameraIds[0], RestoreParamTypeOhos::PERSISTENT_DEFAULT_PARAM_OHOS,
        activeTime, effectParam);
    EXPECT_EQ(intResult, 2);
    cameraIds[0] = "";
    intResult = cameraService_->SetPrelaunchConfig(cameraIds[0], RestoreParamTypeOhos::TRANSIENT_ACTIVE_PARAM_OHOS,
        activeTime, effectParam);
    EXPECT_EQ(intResult, 2);
    intResult = cameraService_->SetPrelaunchConfig(cameraIds[0], RestoreParamTypeOhos::PERSISTENT_DEFAULT_PARAM_OHOS,
        activeTime, effectParam);
    EXPECT_EQ(intResult, 2);
    cameraIds[0] = "";
    intResult = cameraService_->SetPrelaunchConfig(cameraIds[0], RestoreParamTypeOhos::PERSISTENT_DEFAULT_PARAM_OHOS,
        activeTime, effectParam);
    EXPECT_EQ(intResult, 2);

    device->Close();
}

/*
 * Feature: Framework
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test dump with no static capability.
 */
HWTEST_F(HCameraServiceUnit, HCamera_service_unittest_048, TestSize.Level0)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    sptr<ICameraDeviceService> device = nullptr;
    cameraService_->CreateCameraDevice(cameraIds[0], device);
    ASSERT_NE(device, nullptr);
    device->Open();

    cameraService_->OnStart();

    cameraIds = {};
    std::vector<std::shared_ptr<OHOS::Camera::CameraMetadata>> cameraAbilityList = {};
    int32_t ret = cameraService_->GetCameras(cameraIds, cameraAbilityList);

    int fd = 0;
    std::vector<std::u16string> args = {};
    ret = cameraService_->Dump(fd, args);
    EXPECT_EQ(ret, 0);

    std::u16string cameraServiceInfo = u"";
    args.push_back(cameraServiceInfo);
    ret = cameraService_->Dump(fd, args);
    EXPECT_EQ(ret, 0);

    device->Release();
    device->Close();
}

/*
 * Feature: Framework
 * Function: Test HCameraService in UpdateSkinSmoothSetting,
 *              UpdateFaceSlenderSetting, UpdateSkinToneSetting
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test HCameraService in UpdateSkinSmoothSetting,
 *              UpdateFaceSlenderSetting, UpdateSkinToneSetting
 */
HWTEST_F(HCameraServiceUnit, HCamera_service_unittest_049, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    auto hCameraService = new HCameraService(0, true);
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata = cameras[0]->GetMetadata();

    EXPECT_EQ(hCameraService->UpdateSkinSmoothSetting(metadata, 0), CAMERA_OK);
    EXPECT_EQ(hCameraService->UpdateSkinSmoothSetting(metadata, 1), CAMERA_OK);
    EXPECT_EQ(hCameraService->UpdateSkinSmoothSetting(nullptr, 1), CAMERA_OK);
    EXPECT_EQ(hCameraService->UpdateFaceSlenderSetting(metadata, 0), CAMERA_OK);
    EXPECT_EQ(hCameraService->UpdateFaceSlenderSetting(metadata, 1), CAMERA_OK);
    EXPECT_EQ(hCameraService->UpdateFaceSlenderSetting(nullptr, 1), CAMERA_OK);
    EXPECT_EQ(hCameraService->UpdateSkinToneSetting(metadata, 0), CAMERA_OK);
    EXPECT_EQ(hCameraService->UpdateSkinToneSetting(metadata, 1), CAMERA_OK);
    EXPECT_EQ(hCameraService->UpdateSkinToneSetting(nullptr, 1), CAMERA_OK);
}
}
}