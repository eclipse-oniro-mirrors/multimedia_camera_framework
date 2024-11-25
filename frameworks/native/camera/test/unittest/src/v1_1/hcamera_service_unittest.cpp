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

void HCameraServiceUnit::SetUpTestCase(void) {}

void HCameraServiceUnit::TearDownTestCase(void) {}

void HCameraServiceUnit::SetUp()
{
    NativeAuthorization();
    cameraHostManager_ = new HCameraHostManager(nullptr);
    cameraService_ = new HCameraService(cameraHostManager_);
    cameraManager_ = CameraManager::GetInstance();
}

void HCameraServiceUnit::TearDown()
{
    cameraHostManager_ = nullptr;
    cameraService_ = nullptr;
    cameraManager_ = nullptr;
}

void HCameraServiceUnit::NativeAuthorization()
{
    const char *perms[2];
    perms[0] = "ohos.permission.DISTRIBUTED_DATASYNC";
    perms[1] = "ohos.permission.CAMERA";
    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = 2,
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
    MEDIA_DEBUG_LOG("HCameraServiceUnit::NativeAuthorization g_uid:%{public}d", uid_);
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
    std::vector<string> cameraIds;
    for (auto camera : cameras){
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
    cameraHostManager_->Init();
    std::string cameraId = cameras[0]->GetID();
    shared_ptr<OHOS::Camera::CameraMetadata> cameraAbility =
        std::make_shared<OHOS::Camera::CameraMetadata>(METADATA_ITEM_SIZE, METADATA_DATA_SIZE);
    int32_t cameraPosition = 0;
    cameraAbility->addEntry(OHOS_ABILITY_CAMERA_POSITION, &cameraPosition, sizeof(int32_t));
    uint8_t type = 5;
    cameraAbility->addEntry(OHOS_ABILITY_CAMERA_TYPE, &type, sizeof(uint8_t));
    uint8_t value_u8 = 0;
    cameraAbility->addEntry(OHOS_ABILITY_CAMERA_CONNECTION_TYPE, &value_u8, sizeof(uint8_t));
    common_metadata_header_t* metadataEntry = cameraAbility->get();
    CameraInfoDumper infoDumper(0);
    cameraService_->DumpCameraAbility(metadataEntry, infoDumper);
    std::string msgString = infoDumper.dumperString_;
    bool ret = [msgString]()->bool {
        return (msgString.find("Camera Position") != std::string::npos);
    }();
    EXPECT_TRUE(ret);
    ret = [msgString]()->bool {
        return (msgString.find("Camera Type") != std::string::npos);
    }();
    EXPECT_TRUE(ret);
    ret = [msgString]()->bool {
        return (msgString.find("Camera Connection Type") != std::string::npos);
    }();
    EXPECT_TRUE(ret);
}

/*
 * Feature: CameraService
 * Function: Test DumpCameraStreamInfo in class HCameraService
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test DumpCameraStreamInfo
 */
HWTEST_F(HCameraServiceUnit, HCamera_service_unittest_013, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();

    cameraHostManager_->Init();
    std::string cameraId = cameras[0]->GetID();
    shared_ptr<OHOS::Camera::CameraMetadata> cameraAbility = cameras[0]->GetMetadata();
    cameraHostManager_->GetCameraAbility(cameraId, cameraAbility);
    common_metadata_header_t* metadataEntry = cameraAbility->get();
    CameraInfoDumper infoDumper(0);
    cameraService_->DumpCameraStreamInfo(metadataEntry, infoDumper);
    std::string msgString = infoDumper.dumperString_;
    bool ret = [msgString]()->bool {
        return (msgString.find("Basic Stream Info Size") != std::string::npos);
    }();
    EXPECT_TRUE(ret);
    ret = [msgString]()->bool {
        return (msgString.find("Format:[") != std::string::npos);
    }();
    EXPECT_TRUE(ret);
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
    cameraHostManager_->Init();
    std::string cameraId = cameras[0]->GetID();
    shared_ptr<OHOS::Camera::CameraMetadata> cameraAbility =
        std::make_shared<OHOS::Camera::CameraMetadata>(METADATA_ITEM_SIZE, METADATA_DATA_SIZE);

    int32_t zoomCap[2] = {0, 10};
    cameraAbility->addEntry(OHOS_ABILITY_ZOOM_CAP, &zoomCap, sizeof(zoomCap) / sizeof(zoomCap[0]));

    int32_t sceneZoomCap[2] = {1, 10};
    cameraAbility->addEntry(OHOS_ABILITY_SCENE_ZOOM_CAP, &sceneZoomCap, sizeof(zoomCap) / sizeof(zoomCap[0]));

    float value_f[1] = {1.0};
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
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    std::string cameraId = cameras[0]->GetID();
    cameraHostManager_->OpenCameraDevice(cameraId, nullptr, pDevice_, true);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    camInput->GetCameraDevice()->Open();

    std::string deviceId = "";
    cameraService_->OnAddSystemAbility(0, deviceId);
    EXPECT_EQ(deviceId, "");

    input->Close();
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
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    std::string cameraId = cameras[0]->GetID();
    vector<string> cameraIds = {cameraId};
    cameraHostManager_->OpenCameraDevice(cameraId, nullptr, pDevice_, true);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    camInput->GetCameraDevice()->Open();

    cameraService_->isFoldable = false;
    cameraService_->isFoldableInit = false;
    vector<shared_ptr<OHOS::Camera::CameraMetadata>> cameraAbilityList;
    int32_t ret = cameraService_->GetCameras(cameraIds, cameraAbilityList);
    EXPECT_EQ(ret, CAMERA_OK);

    input->Close();
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
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    std::string cameraId = cameras[0]->GetID();
    cameraHostManager_->OpenCameraDevice(cameraId, nullptr, pDevice_, true);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    camInput->GetCameraDevice()->Open();

    shared_ptr<OHOS::Camera::CameraMetadata> cameraAbility =
        std::make_shared<OHOS::Camera::CameraMetadata>(METADATA_ITEM_SIZE, METADATA_DATA_SIZE);
    int32_t cameraPosition = OHOS_CAMERA_POSITION_FRONT;
    cameraAbility->addEntry(OHOS_ABILITY_CAMERA_POSITION, &cameraPosition, sizeof(int32_t));
    int32_t foldType = OHOS_CAMERA_POSITION_OTHER;
    cameraAbility->addEntry(OHOS_ABILITY_CAMERA_FOLDSCREEN_TYPE, &foldType, sizeof(int32_t));
    cameraService_->isFoldable = true;
    shared_ptr<CameraMetaInfo> ret = cameraService_->GetCameraMetaInfo(cameraId, cameraAbility);
    EXPECT_NE(ret, nullptr);

    cameraService_->isFoldable = false;
    ret = cameraService_->GetCameraMetaInfo(cameraId, cameraAbility);
    EXPECT_NE(ret, nullptr);

    cameraPosition = 0;
    cameraAbility->updateEntry(OHOS_ABILITY_CAMERA_POSITION, &cameraPosition, 1);
    ret = cameraService_->GetCameraMetaInfo(cameraId, cameraAbility);
    EXPECT_NE(ret, nullptr);

    foldType = 0;
    cameraAbility->updateEntry(OHOS_ABILITY_CAMERA_FOLDSCREEN_TYPE, &foldType, 1);
    ret = cameraService_->GetCameraMetaInfo(cameraId, cameraAbility);
    EXPECT_NE(ret, nullptr);

    cameraService_->isFoldable = true;
    cameraPosition = OHOS_CAMERA_POSITION_FRONT;
    cameraAbility->updateEntry(OHOS_ABILITY_CAMERA_POSITION, &cameraPosition, 1);
    ret = cameraService_->GetCameraMetaInfo(cameraId, cameraAbility);
    EXPECT_NE(ret, nullptr);

    cameraPosition = 0;
    cameraAbility->updateEntry(OHOS_ABILITY_CAMERA_POSITION, &cameraPosition, 1);
    foldType = OHOS_CAMERA_POSITION_OTHER;
    cameraAbility->updateEntry(OHOS_ABILITY_CAMERA_FOLDSCREEN_TYPE, &foldType, 1);
    ret = cameraService_->GetCameraMetaInfo(cameraId, cameraAbility);
    EXPECT_NE(ret, nullptr);

    input->Close();
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
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    std::string cameraId = cameras[0]->GetID();
    cameraHostManager_->OpenCameraDevice(cameraId, nullptr, pDevice_, true);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    camInput->GetCameraDevice()->Open();

    shared_ptr<OHOS::Camera::CameraMetadata> cameraAbility =
        std::make_shared<OHOS::Camera::CameraMetadata>(METADATA_ITEM_SIZE, METADATA_DATA_SIZE);
    int32_t cameraPosition = OHOS_CAMERA_POSITION_FRONT;
    cameraAbility->addEntry(OHOS_ABILITY_CAMERA_POSITION, &cameraPosition, sizeof(int32_t));
    int32_t foldType = OHOS_CAMERA_FOLDSCREEN_INNER;
    cameraAbility->addEntry(OHOS_ABILITY_CAMERA_FOLDSCREEN_TYPE, &foldType, sizeof(int32_t));
    cameraService_->isFoldable = true;
    shared_ptr<CameraMetaInfo> ret = cameraService_->GetCameraMetaInfo(cameraId, cameraAbility);
    EXPECT_NE(ret, nullptr);

    cameraService_->isFoldable = false;
    ret = cameraService_->GetCameraMetaInfo(cameraId, cameraAbility);
    EXPECT_NE(ret, nullptr);

    cameraPosition = 0;
    cameraAbility->updateEntry(OHOS_ABILITY_CAMERA_POSITION, &cameraPosition, 1);
    ret = cameraService_->GetCameraMetaInfo(cameraId, cameraAbility);
    EXPECT_NE(ret, nullptr);

    foldType = 0;
    cameraAbility->updateEntry(OHOS_ABILITY_CAMERA_FOLDSCREEN_TYPE, &foldType, 1);
    ret = cameraService_->GetCameraMetaInfo(cameraId, cameraAbility);
    EXPECT_NE(ret, nullptr);

    cameraService_->isFoldable = true;
    cameraPosition = OHOS_CAMERA_POSITION_FRONT;
    cameraAbility->updateEntry(OHOS_ABILITY_CAMERA_POSITION, &cameraPosition, 1);
    ret = cameraService_->GetCameraMetaInfo(cameraId, cameraAbility);
    EXPECT_NE(ret, nullptr);

    cameraPosition = 0;
    cameraAbility->updateEntry(OHOS_ABILITY_CAMERA_POSITION, &cameraPosition, 1);
    foldType = OHOS_CAMERA_FOLDSCREEN_INNER;
    cameraAbility->updateEntry(OHOS_ABILITY_CAMERA_FOLDSCREEN_TYPE, &foldType, 1);
    ret = cameraService_->GetCameraMetaInfo(cameraId, cameraAbility);
    EXPECT_NE(ret, nullptr);

    input->Close();
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
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    std::string cameraId = cameras[0]->GetID();
    cameraHostManager_->OpenCameraDevice(cameraId, nullptr, pDevice_, true);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    camInput->GetCameraDevice()->Open();

    cameraService_->cameraServiceCallbacks_ = {};
    cameraService_->cameraStatusCallbacks_ = {};
    cameraService_->OnCameraStatus(cameraId, CameraStatus::CAMERA_STATUS_AVAILABLE, CallbackInvoker::APPLICATION);
    EXPECT_TRUE(cameraService_->cameraStatusCallbacks_.empty());

    sptr<ICameraServiceCallbackTest> callback = new ICameraServiceCallbackTest();
    cameraService_->cameraServiceCallbacks_ = {{1, callback}, {2, nullptr}};
    cameraService_->OnCameraStatus(cameraId, CameraStatus::CAMERA_STATUS_AVAILABLE, CallbackInvoker::APPLICATION);
    EXPECT_EQ(cameraService_->cameraStatusCallbacks_.size(), 1);

    callback = nullptr;
    input->Close();
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
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    std::string cameraId = cameras[0]->GetID();
    cameraHostManager_->OpenCameraDevice(cameraId, nullptr, pDevice_, true);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    camInput->GetCameraDevice()->Open();

    cameraService_->cameraServiceCallbacks_ = {};
    cameraService_->OnFlashlightStatus(cameraId, FlashStatus::FLASH_STATUS_OFF);
    EXPECT_TRUE(cameraService_->cameraServiceCallbacks_.empty());

    sptr<ICameraServiceCallbackTest> callback = new ICameraServiceCallbackTest();
    cameraService_->cameraServiceCallbacks_ = {{1, callback}, {2, nullptr}};
    cameraService_->OnFlashlightStatus(cameraId, FlashStatus::FLASH_STATUS_OFF);
    EXPECT_EQ(cameraService_->cameraServiceCallbacks_.size(), 2);

    callback = nullptr;
    input->Close();
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
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    std::string cameraId = cameras[0]->GetID();
    cameraHostManager_->OpenCameraDevice(cameraId, nullptr, pDevice_, true);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    camInput->GetCameraDevice()->Open();

    cameraService_->cameraMuteServiceCallbacks_ = {};
    cameraService_->peerCallback_ = new ICameraBrokerTest();
    cameraService_->OnMute(true);
    EXPECT_TRUE(cameraService_->cameraMuteServiceCallbacks_.empty());

    sptr<ICameraMuteServiceCallbackTest> callback = new ICameraMuteServiceCallbackTest();
    cameraService_->cameraMuteServiceCallbacks_ = {{1, callback}, {2, nullptr}};
    cameraService_->OnMute(true);
    EXPECT_EQ(cameraService_->cameraMuteServiceCallbacks_.size(), 2);

    cameraService_->peerCallback_ = nullptr;
    callback = nullptr;
    input->Close();
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
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    std::string cameraId = cameras[0]->GetID();
    cameraHostManager_->OpenCameraDevice(cameraId, nullptr, pDevice_, true);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    camInput->GetCameraDevice()->Open();

    uint32_t callingTokenId = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDevice> activeDevice = new HCameraDevice(cameraHostManager_, cameraId, callingTokenId);
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

    input->Close();
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
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    std::string cameraId = cameras[0]->GetID();
    cameraHostManager_->OpenCameraDevice(cameraId, nullptr, pDevice_, true);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    camInput->GetCameraDevice()->Open();

    cameraService_->torchServiceCallbacks_ = {};
    cameraService_->OnTorchStatus(TorchStatus::TORCH_STATUS_OFF);
    EXPECT_TRUE(cameraService_->torchServiceCallbacks_.empty());

    sptr<ITorchServiceCallbackTest> callback = new ITorchServiceCallbackTest();
    cameraService_->torchServiceCallbacks_ = {{1, callback}, {2, nullptr}};
    cameraService_->OnTorchStatus(TorchStatus::TORCH_STATUS_OFF);
    EXPECT_EQ(cameraService_->torchServiceCallbacks_.size(), 2);

    callback = nullptr;
    input->Close();
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
}
}
}

