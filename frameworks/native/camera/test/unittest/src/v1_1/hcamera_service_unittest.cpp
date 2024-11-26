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
namespace OHOS {
namespace CameraStandard {
using namespace OHOS::HDI::Camera::V1_1;
void HCameraServiceUnit::SetUpTestCase(void) {}

void HCameraServiceUnit::TearDownTestCase(void) {}

void HCameraServiceUnit::SetUp()
{
    NativeAuthorization();
    mockFlagWithoutAbt_ = false;
    mockCameraHostManager_ = new MockHCameraHostManager(nullptr);
    mockCameraDevice_ = mockCameraHostManager_->cameraDevice;
    mockStreamOperator_ = mockCameraDevice_->streamOperator;
    mockHCameraService_ = new FakeHCameraService(mockCameraHostManager_);
    cameraManager_ = new FakeCameraManager(new FakeHCameraService(mockCameraHostManager_));
    mockCameraManager_ = new MockCameraManager();
}

void HCameraServiceUnit::TearDown()
{
    Mock::AllowLeak(mockStreamOperator_);
    Mock::AllowLeak(mockCameraDevice_);
    Mock::AllowLeak(mockHCameraService_);
    Mock::AllowLeak(mockCameraManager_);
    Mock::AllowLeak(mockCameraHostManager_);
    mockStreamOperator_ = nullptr;
    mockCameraDevice_ = nullptr;
    mockHCameraService_ = nullptr;
    mockCameraManager_ = nullptr;
    mockCameraHostManager_ = nullptr;
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
    InSequence s;
    EXPECT_CALL(*mockCameraHostManager_, OpenCameraDevice(_, _, _, _));
    sptr<HCameraHostManager> cameraHostManager = (sptr<HCameraHostManager> &)mockCameraHostManager_;
    sptr<HCameraService> cameraService = new HCameraService(cameraHostManager);
    EXPECT_NE(cameraService, nullptr);
    cameraService->OnStart();
    cameraService->OnDump();
    cameraService->OnStop();
    cameraService = nullptr;
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
    InSequence s;
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    EXPECT_NE(cameras.size(), 0);
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);

    EXPECT_CALL(*mockCameraHostManager_, OpenCameraDevice(_, _, _, _));
    EXPECT_CALL(*mockCameraDevice_, SetResultMode(ON_CHANGED));
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    sptr<HCameraHostManager> cameraHostManager = (sptr<HCameraHostManager> &)mockCameraHostManager_;
    sptr<HCameraService> cameraService = new HCameraService(cameraHostManager);
    ASSERT_NE(cameraService, nullptr);

    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    sptr<IBufferProducer> producer = surface->GetProducer();
    ASSERT_NE(producer, nullptr);

    int32_t height = 0;
    int32_t width = PHOTO_DEFAULT_WIDTH;
    sptr<IStreamCapture> output = nullptr;

    int32_t intResult = cameraService->CreatePhotoOutput(producer, 0, width, height, output);
    EXPECT_EQ(intResult, CAMERA_INVALID_ARG);

    width = 0;
    height = PHOTO_DEFAULT_HEIGHT;
    intResult = cameraService->CreatePhotoOutput(producer, 0, width, height, output);
    EXPECT_EQ(intResult, CAMERA_INVALID_ARG);

    input->Close();
    cameraService = nullptr;
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
    InSequence s;
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    EXPECT_NE(cameras.size(), 0);
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    EXPECT_CALL(*mockCameraHostManager_, OpenCameraDevice(_, _, _, _));
    EXPECT_CALL(*mockCameraDevice_, SetResultMode(ON_CHANGED));
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    sptr<HCameraHostManager> cameraHostManager = (sptr<HCameraHostManager> &)mockCameraHostManager_;
    sptr<HCameraService> cameraService = new HCameraService(cameraHostManager);
    ASSERT_NE(cameraService, nullptr);

    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    sptr<IBufferProducer> producer = surface->GetProducer();
    ASSERT_NE(producer, nullptr);

    int32_t width = PREVIEW_DEFAULT_WIDTH;
    int32_t height = 0;
    sptr<IStreamRepeat> output = nullptr;

    int32_t intResult = cameraService->CreatePreviewOutput(producer, 0, width, height, output);
    EXPECT_EQ(intResult, CAMERA_INVALID_ARG);

    width = 0;
    intResult = cameraService->CreatePreviewOutput(producer, 0, width, height, output);
    EXPECT_EQ(intResult, CAMERA_INVALID_ARG);
    input->Close();
    cameraService = nullptr;
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
    InSequence s;
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    EXPECT_NE(cameras.size(), 0);
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);

    EXPECT_CALL(*mockCameraHostManager_, OpenCameraDevice(_, _, _, _));
    EXPECT_CALL(*mockCameraDevice_, SetResultMode(ON_CHANGED));
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    sptr<HCameraHostManager> cameraHostManager = (sptr<HCameraHostManager> &)mockCameraHostManager_;
    sptr<HCameraService> cameraService = new HCameraService(cameraHostManager);
    ASSERT_NE(cameraService, nullptr);

    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    sptr<IBufferProducer> producer = surface->GetProducer();
    ASSERT_NE(producer, nullptr);

    int32_t height = 0;
    int32_t width = PHOTO_DEFAULT_WIDTH;
    sptr<IStreamDepthData> output = nullptr;

    int32_t intResult = cameraService->CreateDepthDataOutput(producer, 0, width, height, output);
    EXPECT_EQ(intResult, CAMERA_INVALID_ARG);

    width = 0;
    intResult = cameraService->CreateDepthDataOutput(producer, 0, width, height, output);
    EXPECT_EQ(intResult, CAMERA_INVALID_ARG);

    intResult = cameraService->CreateDepthDataOutput(nullptr, 0, width, height, output);
    EXPECT_EQ(intResult, CAMERA_INVALID_ARG);

    producer = surface->GetProducer();
    ASSERT_NE(producer, nullptr);
    width = PHOTO_DEFAULT_WIDTH;
    height = PHOTO_DEFAULT_HEIGHT;

    intResult = cameraService->CreateDepthDataOutput(producer, 0, width, height, output);
    EXPECT_EQ(intResult, CAMERA_OK);

    input->Close();
    cameraService = nullptr;
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
    InSequence s;
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    EXPECT_NE(cameras.size(), 0);
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);

    EXPECT_CALL(*mockCameraHostManager_, OpenCameraDevice(_, _, _, _));
    EXPECT_CALL(*mockCameraDevice_, SetResultMode(ON_CHANGED));
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    sptr<HCameraHostManager> cameraHostManager = (sptr<HCameraHostManager> &)mockCameraHostManager_;
    sptr<HCameraService> cameraService = new HCameraService(cameraHostManager);
    ASSERT_NE(cameraService, nullptr);

    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    sptr<IBufferProducer> producer = surface->GetProducer();
    ASSERT_NE(producer, nullptr);

    int32_t height = 0;
    int32_t width = PHOTO_DEFAULT_WIDTH;
    sptr<IStreamRepeat> output = nullptr;
    int32_t intResult = cameraService->CreateVideoOutput(producer, 0, width, height, output);
    EXPECT_EQ(intResult, CAMERA_INVALID_ARG);

    width = 0;
    intResult = cameraService->CreateVideoOutput(producer, 0, width, height, output);
    EXPECT_EQ(intResult, CAMERA_INVALID_ARG);

    producer = nullptr;
    intResult = cameraService->CreateVideoOutput(producer, 0, width, height, output);
    EXPECT_EQ(intResult, CAMERA_INVALID_ARG);

    producer = surface->GetProducer();
    ASSERT_NE(producer, nullptr);
    width = PHOTO_DEFAULT_WIDTH;
    height = PHOTO_DEFAULT_HEIGHT;
    intResult = cameraService->CreateVideoOutput(producer, 0, width, height, output);
    EXPECT_EQ(intResult, 0);

    input->Close();
    cameraService = nullptr;
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
    sptr<HCameraHostManager> cameraHostManager = (sptr<HCameraHostManager> &)mockCameraHostManager_;
    sptr<HCameraService> cameraService = new HCameraService(cameraHostManager);
    OHOS::Rosen::FoldStatus foldStatus = OHOS::Rosen::FoldStatus::HALF_FOLD;
    cameraService->preFoldStatus_ = FoldStatus::EXPAND;
    cameraService->OnFoldStatusChanged(foldStatus);
    EXPECT_EQ(cameraService->preFoldStatus_, FoldStatus::HALF_FOLD);

    foldStatus = OHOS::Rosen::FoldStatus::EXPAND;
    cameraService->preFoldStatus_ = FoldStatus::HALF_FOLD;
    cameraService->OnFoldStatusChanged(foldStatus);
    EXPECT_EQ(cameraService->preFoldStatus_, FoldStatus::EXPAND);
    cameraService = nullptr;
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
    sptr<HCameraHostManager> cameraHostManager = (sptr<HCameraHostManager> &)mockCameraHostManager_;
    sptr<HCameraService> cameraService = new HCameraService(cameraHostManager);
    cameraService->RegisterFoldStatusListener();
    EXPECT_TRUE(cameraService->isFoldRegister);
    cameraService->UnRegisterFoldStatusListener();
    EXPECT_FALSE(cameraService->isFoldRegister);
    cameraService = nullptr;
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
    InSequence s;
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    EXPECT_NE(cameras.size(), 0);
    sptr<HCameraHostManager> cameraHostManager = (sptr<HCameraHostManager> &)mockCameraHostManager_;
    sptr<HCameraService> cameraService = new HCameraService(cameraHostManager);
    std::string cameraId = cameras[0]->GetID();
    int32_t state = 0;
    bool canOpenCamera = false;
    int32_t ret = cameraService->AllowOpenByOHSide(cameraId, state, canOpenCamera);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_TRUE(canOpenCamera);
    cameraService = nullptr;
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
    InSequence s;
    sptr<HCameraHostManager> cameraHostManager = (sptr<HCameraHostManager> &)mockCameraHostManager_;
    sptr<HCameraService> cameraService = new HCameraService(cameraHostManager);
    sptr<ICameraBroker> callback = nullptr;
    int32_t ret = cameraService->SetPeerCallback(callback);
    EXPECT_EQ(ret, CAMERA_INVALID_ARG);
    cameraService = nullptr;
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
    InSequence s;
    sptr<HCameraHostManager> cameraHostManager = (sptr<HCameraHostManager> &)mockCameraHostManager_;
    sptr<HCameraService> cameraService = new HCameraService(cameraHostManager);
    int32_t ret = cameraService->UnsetPeerCallback();
    EXPECT_EQ(ret, CAMERA_OK);
    cameraService = nullptr;
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
    InSequence s;
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    EXPECT_NE(cameras.size(), 0);
    sptr<HCameraHostManager> cameraHostManager = (sptr<HCameraHostManager> &)mockCameraHostManager_;
    sptr<HCameraService> cameraService = new HCameraService(cameraHostManager);
    std::vector<string> cameraIds;
    for (auto camera : cameras) {
        std::string cameraId = camera->GetID();
        cameraIds.push_back(cameraId);
    }
    EXPECT_NE(cameraIds.size(), 0);
    CameraInfoDumper infoDumper(0);
    cameraService->DumpCameraSummary(cameraIds, infoDumper);
    std::string msgString = infoDumper.dumperString_;
    auto ret = [msgString]()->bool {
        return (msgString.find("Number of Camera clients") != std::string::npos);
    }();
    EXPECT_TRUE(ret);
    cameraService = nullptr;
}

}
}

