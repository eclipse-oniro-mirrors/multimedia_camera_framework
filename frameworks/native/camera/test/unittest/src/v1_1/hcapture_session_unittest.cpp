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

#include "hcapture_session_unittest.h"

#include "access_token.h"
#include "accesstoken_kit.h"
#include "camera_log.h"
#include "camera_util.h"
#include "hap_token_info.h"
#include "ipc_skeleton.h"
#include "metadata_utils.h"
#include "nativetoken_kit.h"
#include "surface.h"
#include "test_common.h"
#include "token_setproc.h"
#include "os_account_manager.h"
#include "picture.h"

namespace OHOS {
namespace CameraStandard {
using namespace OHOS::HDI::Camera::V1_1;
constexpr static int32_t INTERFACE_CODE = 7;
constexpr static int32_t DEFAULT_WIDTH = 1280;
constexpr static int32_t DEFAULT_HEIGHT = 960;
constexpr static int32_t DEFAULT_FORMAT = 4;

void HCaptureSessionUnitTest::SetUpTestCase(void)
{
    MEDIA_DEBUG_LOG("HCaptureSessionUnitTest::SetUpTestCase started!");
}

void HCaptureSessionUnitTest::TearDownTestCase(void)
{
    MEDIA_DEBUG_LOG("HCaptureSessionUnitTest::TearDownTestCase started!");
}

void HCaptureSessionUnitTest::SetUp()
{
    NativeAuthorization();
    mockCameraHostManager_ = new MockHCameraHostManager(nullptr);
    cameraManager_ = new FakeCameraManager(new FakeHCameraService(mockCameraHostManager_));
}

void HCaptureSessionUnitTest::TearDown()
{
    Mock::AllowLeak(mockCameraHostManager_);

    if (cameraManager_) {
        cameraManager_ = nullptr;
    }
    if (mockCameraHostManager_) {
        mockCameraHostManager_ = nullptr;
    }
}

void HCaptureSessionUnitTest::NativeAuthorization()
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
    MEDIA_DEBUG_LOG("HCaptureSessionUnitTest::NativeAuthorization g_uid:%{public}d", uid_);
    SetSelfTokenID(tokenId_);
    OHOS::Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
}

/*
 * Feature: HCaptureSession
 * Function: Test current stream infos are not empty after config normal streams
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test current stream infos are not empty after config normal streams
 */
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("hcapture_session_unit_test_001 start");

    auto cameras = cameraManager_->GetSupportedCameras();
    auto input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    input->GetCameraDevice()->Open();

    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCaptureSession> session = new (std::nothrow) HCaptureSession(callerToken, SceneMode::NORMAL);
    ASSERT_NE(session, nullptr);

    EXPECT_EQ(session->BeginConfig(), CAMERA_OK);
    sptr<ICameraDeviceService> device = input->GetCameraDevice();
    EXPECT_EQ(session->AddInput(device), CAMERA_OK);

    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    sptr<IBufferProducer> producer = surface->GetProducer();

    sptr<HStreamRepeat> streamRepeat = new (std::nothrow) HStreamRepeat(producer, DEFAULT_FORMAT,
        DEFAULT_WIDTH, DEFAULT_HEIGHT, RepeatStreamType::PREVIEW);
    ASSERT_NE(streamRepeat, nullptr);
    sptr<HStreamCapture> streamCapture = new (std::nothrow) HStreamCapture(producer, DEFAULT_FORMAT,
        DEFAULT_WIDTH, DEFAULT_HEIGHT);
    ASSERT_NE(streamCapture, nullptr);

    EXPECT_EQ(session->AddOutput(StreamType::REPEAT, streamRepeat), CAMERA_OK);
    EXPECT_EQ(session->AddOutput(StreamType::CAPTURE, streamCapture), CAMERA_OK);
    session->CommitConfig();
    session->Start();

    std::vector<StreamInfo_V1_1> streamInfos = {};
    EXPECT_EQ(session->GetCurrentStreamInfos(streamInfos), CAMERA_OK);
    ASSERT_TRUE(streamInfos.size() != 0);

    session->Stop();
    EXPECT_EQ(input->Close(), CAMERA_OK);
    EXPECT_EQ(session->Release(), CAMERA_OK);
    session = nullptr;

    MEDIA_INFO_LOG("hcapture_session_unit_test_001 end");
}

/*
 * Feature: HCaptureSession
 * Function: Test multiple add camera device, CanAddInput interface is not supported,
 * and commit comfig return camera invalid session cfg
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test multiple add camera device, CanAddInput interface is not supported,
 * and commit comfig return camera invalid session cfg
 */
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("hcapture_session_unit_test_002 start");

    auto cameras = cameraManager_->GetSupportedCameras();
    auto input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    input->GetCameraDevice()->Open();

    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCaptureSession> session = new (std::nothrow) HCaptureSession(callerToken, SceneMode::NORMAL);
    ASSERT_NE(session, nullptr);

    bool result = false;
    EXPECT_EQ(session->BeginConfig(), CAMERA_OK);
    sptr<ICameraDeviceService> device = input->GetCameraDevice();
    EXPECT_EQ(session->CanAddInput(device, result), CAMERA_OK);
    ASSERT_TRUE(result);
    EXPECT_EQ(session->AddInput(device), CAMERA_OK);

    EXPECT_EQ(session->CanAddInput(device, result), CAMERA_INVALID_SESSION_CFG);
    ASSERT_TRUE(!result);
    EXPECT_EQ(session->AddInput(device), CAMERA_INVALID_SESSION_CFG);
    EXPECT_EQ(session->CommitConfig(), CAMERA_INVALID_SESSION_CFG);

    EXPECT_EQ(input->Close(), CAMERA_OK);
    EXPECT_EQ(session->Release(), CAMERA_OK);
    session = nullptr;

    MEDIA_INFO_LOG("hcapture_session_unit_test_002 end");
}

/*
 * Feature: HCaptureSession
 * Function: Test register display listener can be called normally when set preview rotation
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test register display listener can be called normally when set preview rotation
 */
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_003, TestSize.Level0)
{
    MEDIA_INFO_LOG("hcapture_session_unit_test_003 start");

    auto cameras = cameraManager_->GetSupportedCameras();
    auto input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    input->GetCameraDevice()->Open();

    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCaptureSession> session = new (std::nothrow) HCaptureSession(callerToken, SceneMode::NORMAL);
    ASSERT_NE(session, nullptr);
    std::string deviceClass{"device/0"};
    EXPECT_EQ(session->SetPreviewRotation(deviceClass), CAMERA_OK);

    EXPECT_EQ(session->BeginConfig(), CAMERA_OK);
    sptr<ICameraDeviceService> device = input->GetCameraDevice();
    EXPECT_EQ(session->AddInput(device), CAMERA_OK);

    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    sptr<IBufferProducer> producer = surface->GetProducer();
    sptr<HStreamRepeat> streamRepeat = new (std::nothrow) HStreamRepeat(producer, DEFAULT_FORMAT,
        DEFAULT_WIDTH, DEFAULT_HEIGHT, RepeatStreamType::PREVIEW);
    ASSERT_NE(streamRepeat, nullptr);

    EXPECT_EQ(session->AddOutput(StreamType::REPEAT, streamRepeat), CAMERA_OK);
    EXPECT_EQ(session->RemoveOutput(StreamType::REPEAT, streamRepeat), CAMERA_OK);
    EXPECT_EQ(session->CommitConfig(), CAMERA_INVALID_SESSION_CFG);

    EXPECT_EQ(input->Close(), CAMERA_OK);
    EXPECT_EQ(session->Release(), CAMERA_OK);
    session = nullptr;

    MEDIA_INFO_LOG("hcapture_session_unit_test_003 end");
}

/*
 * Feature: HCaptureSession
 * Function: Test delete camera device after config normal stream, commit config return
 * camera invalid session cfg
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test delete camera device after config normal stream, commit config return
 * camera invalid session cfg
 */
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_004, TestSize.Level0)
{
    MEDIA_INFO_LOG("hcapture_session_unit_test_004 start");

    auto cameras = cameraManager_->GetSupportedCameras();
    auto input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    input->GetCameraDevice()->Open();

    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCaptureSession> session = new (std::nothrow) HCaptureSession(callerToken, SceneMode::NORMAL);
    ASSERT_NE(session, nullptr);

    EXPECT_EQ(session->BeginConfig(), CAMERA_OK);
    sptr<ICameraDeviceService> device = input->GetCameraDevice();
    EXPECT_EQ(session->AddInput(device), CAMERA_OK);
    auto cameraDevice = session->GetCameraDevice();
    if (cameraDevice != nullptr) {
        cameraDevice->Release();
        session->SetCameraDevice(nullptr);
    }

    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    sptr<IBufferProducer> producer = surface->GetProducer();
    sptr<HStreamRepeat> streamRepeat = new (std::nothrow) HStreamRepeat(producer, DEFAULT_FORMAT,
        DEFAULT_WIDTH, DEFAULT_HEIGHT, RepeatStreamType::PREVIEW);
    ASSERT_NE(streamRepeat, nullptr);

    EXPECT_EQ(session->AddOutput(StreamType::REPEAT, streamRepeat), CAMERA_OK);
    EXPECT_EQ(session->CommitConfig(), CAMERA_INVALID_SESSION_CFG);

    EXPECT_EQ(input->Close(), CAMERA_OK);
    EXPECT_EQ(session->Release(), CAMERA_OK);
    session = nullptr;

    MEDIA_INFO_LOG("hcapture_session_unit_test_004 end");
}

/*
 * Feature: HCaptureSession
 * Function: Test secure camera when mode is secure but seqId is different, commit config return
 * camera operator not allowed
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test secure camera when mode is secure but seqId is different, commit config return
 * camera operator not allowed
 */
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_005, TestSize.Level0)
{
    MEDIA_INFO_LOG("hcapture_session_unit_test_005 start");

    auto cameras = cameraManager_->GetSupportedCameras();
    for (auto camDevice : cameras) {
        std::vector<SceneMode> modes = cameraManager_->GetSupportedModes(camDevice);
        ASSERT_TRUE(modes.size() != 0);

        if (find(modes.begin(), modes.end(), SceneMode::SECURE) != modes.end()) {
            auto input = cameraManager_->CreateCameraInput(camDevice);
            ASSERT_NE(input, nullptr);
            uint64_t secureSeqId = 1;
            input->Open(true, &secureSeqId);

            uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
            sptr<HCaptureSession> session = new (std::nothrow) HCaptureSession(callerToken, SceneMode::SECURE);
            ASSERT_NE(session, nullptr);

            EXPECT_EQ(session->BeginConfig(), CAMERA_OK);
            sptr<ICameraDeviceService> device = input->GetCameraDevice();
            EXPECT_EQ(session->AddInput(device), CAMERA_OK);
            EXPECT_EQ(session->CommitConfig(), CAMERA_OPERATION_NOT_ALLOWED);

            EXPECT_EQ(input->Close(), CAMERA_OK);
            EXPECT_EQ(session->Release(), CAMERA_OK);
            session = nullptr;
        }
    }

    MEDIA_INFO_LOG("hcapture_session_unit_test_005 end");
}

/*
 * Feature: HCaptureSession
 * Function: Test set color space interface, when color space format not match and need update,
 * result return camera operator not allowed
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * Function: Test set color space interface, when color space format not match and need update,
 * result return camera operator not allowed
 */
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_006, TestSize.Level0)
{
    MEDIA_INFO_LOG("hcapture_session_unit_test_006 start");

    auto cameras = cameraManager_->GetSupportedCameras();
    auto input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    input->GetCameraDevice()->Open();

    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCaptureSession> session = new (std::nothrow) HCaptureSession(callerToken, SceneMode::NORMAL);
    ASSERT_NE(session, nullptr);

    EXPECT_EQ(session->BeginConfig(), CAMERA_OK);
    sptr<ICameraDeviceService> device = input->GetCameraDevice();
    EXPECT_EQ(session->AddInput(device), CAMERA_OK);

    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    sptr<IBufferProducer> producer = surface->GetProducer();
    sptr<HStreamRepeat> streamRepeat = new (std::nothrow) HStreamRepeat(producer, DEFAULT_FORMAT,
        DEFAULT_WIDTH, DEFAULT_HEIGHT, RepeatStreamType::PREVIEW);
    ASSERT_NE(streamRepeat, nullptr);
    EXPECT_EQ(session->AddOutput(StreamType::REPEAT, streamRepeat), CAMERA_OK);
    session->CommitConfig();

    EXPECT_EQ(session->SetColorSpace(ColorSpace::BT2020_HLG,
        ColorSpace::BT2020_HLG, true), CAMERA_OPERATION_NOT_ALLOWED);

    EXPECT_EQ(input->Close(), CAMERA_OK);
    EXPECT_EQ(session->Release(), CAMERA_OK);
    session = nullptr;

    MEDIA_INFO_LOG("hcapture_session_unit_test_006 end");
}

/*
 * Feature: HCaptureSession
 * Function: Test cancel stream and get stream infos with capture session configure preview stream,
 * metadata stream and capture stream
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test cancel stream and get stream infos with capture session configure preview stream,
 * metadata stream and capture stream
 */
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_007, TestSize.Level0)
{
    MEDIA_INFO_LOG("hcapture_session_unit_test_007 start");

    auto cameras = cameraManager_->GetSupportedCameras();
    auto input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    input->GetCameraDevice()->Open();

    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCaptureSession> session = new (std::nothrow) HCaptureSession(callerToken, SceneMode::NORMAL);
    ASSERT_NE(session, nullptr);

    EXPECT_EQ(session->BeginConfig(), CAMERA_OK);
    sptr<ICameraDeviceService> device = input->GetCameraDevice();
    EXPECT_EQ(session->AddInput(device), CAMERA_OK);

    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    sptr<IBufferProducer> producer = surface->GetProducer();

    sptr<HStreamRepeat> streamRepeat = new (std::nothrow) HStreamRepeat(producer, DEFAULT_FORMAT,
        DEFAULT_WIDTH, DEFAULT_HEIGHT, RepeatStreamType::PREVIEW);
    ASSERT_NE(streamRepeat, nullptr);
    sptr<HStreamMetadata> streamMetadata= new(std::nothrow) HStreamMetadata(producer, 0, {1});
    ASSERT_NE(streamMetadata, nullptr);
    sptr<HStreamCapture> streamCapture = new (std::nothrow) HStreamCapture(producer, DEFAULT_FORMAT,
        DEFAULT_WIDTH, DEFAULT_HEIGHT);
    ASSERT_NE(streamCapture, nullptr);

    EXPECT_EQ(session->AddOutput(StreamType::REPEAT, streamRepeat), CAMERA_OK);
    EXPECT_EQ(session->AddOutput(StreamType::METADATA, streamMetadata), CAMERA_OK);
    EXPECT_EQ(session->AddOutput(StreamType::CAPTURE, streamCapture), CAMERA_OK);
    session->CommitConfig();
    session->Start();

    std::vector<StreamInfo_V1_1> streamInfos = {};
    session->CancelStreamsAndGetStreamInfos(streamInfos);
    ASSERT_TRUE(streamInfos.size() != 0);

    session->Stop();
    EXPECT_EQ(input->Close(), CAMERA_OK);
    EXPECT_EQ(session->Release(), CAMERA_OK);
    session = nullptr;

    MEDIA_INFO_LOG("hcapture_session_unit_test_007 end");
}

/*
 * Feature: HCaptureSession
 * Function: Test in the case of EnableMovingPhoto, live photo stream can start,
 * preview and null streams can not
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test in the case of EnableMovingPhoto, live photo stream can start,
 * preview and null streams can not
 */
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_008, TestSize.Level0)
{
    MEDIA_INFO_LOG("hcapture_session_unit_test_008 start");

    auto cameras = cameraManager_->GetSupportedCameras();
    auto input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    input->GetCameraDevice()->Open();

    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCaptureSession> session = new (std::nothrow) HCaptureSession(callerToken, SceneMode::NORMAL);
    ASSERT_NE(session, nullptr);

    EXPECT_EQ(session->BeginConfig(), CAMERA_OK);
    sptr<ICameraDeviceService> device = input->GetCameraDevice();
    EXPECT_EQ(session->AddInput(device), CAMERA_OK);

    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    sptr<IBufferProducer> producer = surface->GetProducer();
    sptr<HStreamRepeat> streamRepeat = new (std::nothrow) HStreamRepeat(producer, DEFAULT_FORMAT,
        DEFAULT_WIDTH, DEFAULT_HEIGHT, RepeatStreamType::PREVIEW);
    ASSERT_NE(streamRepeat, nullptr);
    sptr<HStreamRepeat> streamRepeat1 = new (std::nothrow) HStreamRepeat(nullptr, DEFAULT_FORMAT,
        DEFAULT_WIDTH, DEFAULT_HEIGHT, RepeatStreamType::PREVIEW);
    ASSERT_NE(streamRepeat1, nullptr);
    sptr<HStreamRepeat> streamRepeat2 = new (std::nothrow) HStreamRepeat(producer, DEFAULT_FORMAT,
        DEFAULT_WIDTH, DEFAULT_HEIGHT, RepeatStreamType::LIVEPHOTO);
    ASSERT_NE(streamRepeat2, nullptr);
    sptr<HStreamRepeat> streamRepeat3 = new (std::nothrow) HStreamRepeat(nullptr, DEFAULT_FORMAT,
        DEFAULT_WIDTH, DEFAULT_HEIGHT, RepeatStreamType::LIVEPHOTO);
    ASSERT_NE(streamRepeat3, nullptr);

    EXPECT_EQ(session->AddOutput(StreamType::REPEAT, streamRepeat), CAMERA_OK);
    EXPECT_EQ(session->AddOutput(StreamType::REPEAT, streamRepeat1), CAMERA_OK);
    EXPECT_EQ(session->AddOutput(StreamType::REPEAT, streamRepeat2), CAMERA_OK);
    EXPECT_EQ(session->AddOutput(StreamType::REPEAT, streamRepeat3), CAMERA_OK);
    session->CommitConfig();

    EXPECT_EQ(session->EnableMovingPhoto(true), CAMERA_OK);
    session->StartMovingPhoto(streamRepeat2);

    EXPECT_EQ(session->EnableMovingPhoto(false), CAMERA_OK);
    session->Start();

    session->Stop();
    EXPECT_EQ(input->Close(), CAMERA_OK);
    EXPECT_EQ(session->Release(), CAMERA_OK);
    session = nullptr;

    MEDIA_INFO_LOG("hcapture_session_unit_test_008 end");
}

/*
 * Feature: HCaptureSession
 * Function: Test operate permission check, when interfaceCode unequal calling token id,
 * return camera operator not allowed
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * Function: Test operate permission check, when interfaceCode unequal calling token id,
 * return camera operator not allowed
 */
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_009, TestSize.Level0)
{
    MEDIA_INFO_LOG("hcapture_session_unit_test_009 start");

    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    uint32_t callerToken1 = ++callerToken;
    sptr<HCaptureSession> session = new (std::nothrow) HCaptureSession(callerToken1, SceneMode::NORMAL);
    ASSERT_NE(session, nullptr);

    EXPECT_EQ(session->OperatePermissionCheck(INTERFACE_CODE), CAMERA_OPERATION_NOT_ALLOWED);
    EXPECT_EQ(session->Release(), CAMERA_OK);
    session = nullptr;

    MEDIA_INFO_LOG("hcapture_session_unit_test_009 end");
}

/*
 * Feature: HCaptureSession
 * Function: Test capture session get pid and destory stub object by pid
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test capture session get pid and destory stub object by pid
 */
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_010, TestSize.Level0)
{
    MEDIA_INFO_LOG("hcapture_session_unit_test_010 start");

    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCaptureSession> session = new (std::nothrow) HCaptureSession(callerToken, SceneMode::NORMAL);
    ASSERT_NE(session, nullptr);
    pid_t pid = session->GetPid();
    session->DestroyStubObjectForPid(pid);
    session = nullptr;

    MEDIA_INFO_LOG("hcapture_session_unit_test_010 end");
}

/*
 * Feature: HCaptureSession
 * Function: Test dump session info with capture session configure preview stream and photo stream
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test dump session info with capture session configure preview stream and photo stream
 */
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_011, TestSize.Level0)
{
    MEDIA_INFO_LOG("hcapture_session_unit_test_011 start");

    auto cameras = cameraManager_->GetSupportedCameras();
    auto input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    input->GetCameraDevice()->Open();

    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCaptureSession> session = new (std::nothrow) HCaptureSession(callerToken, SceneMode::NORMAL);
    ASSERT_NE(session, nullptr);

    EXPECT_EQ(session->BeginConfig(), CAMERA_OK);
    sptr<ICameraDeviceService> device = input->GetCameraDevice();
    EXPECT_EQ(session->AddInput(device), CAMERA_OK);

    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    sptr<IBufferProducer> producer = surface->GetProducer();

    sptr<HStreamRepeat> streamRepeat = new (std::nothrow) HStreamRepeat(producer, DEFAULT_FORMAT,
        DEFAULT_WIDTH, DEFAULT_HEIGHT, RepeatStreamType::PREVIEW);
    ASSERT_NE(streamRepeat, nullptr);
    sptr<HStreamCapture> streamCapture = new (std::nothrow) HStreamCapture(producer, DEFAULT_FORMAT,
        DEFAULT_WIDTH, DEFAULT_HEIGHT);
    ASSERT_NE(streamCapture, nullptr);

    EXPECT_EQ(session->AddOutput(StreamType::REPEAT, streamRepeat), CAMERA_OK);
    EXPECT_EQ(session->AddOutput(StreamType::CAPTURE, streamCapture), CAMERA_OK);
    session->CommitConfig();
    session->Start();

    CameraInfoDumper infoDumper(0);
    session->DumpSessionInfo(infoDumper);

    session->Stop();
    EXPECT_EQ(input->Close(), CAMERA_OK);
    EXPECT_EQ(session->Release(), CAMERA_OK);
    session = nullptr;

    MEDIA_INFO_LOG("hcapture_session_unit_test_011 end");
}

/*
 * Feature: HCaptureSession
 * Function: Test get output status with capture session configure null preview stream,
 * normal preview stream and video stream
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test get output status with capture session configure null preview stream,
 * normal preview stream and video stream
 */
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_012, TestSize.Level0)
{
    MEDIA_INFO_LOG("hcapture_session_unit_test_012 start");

    auto cameras = cameraManager_->GetSupportedCameras();
    auto input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    input->GetCameraDevice()->Open();

    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCaptureSession> session = new (std::nothrow) HCaptureSession(callerToken, SceneMode::NORMAL);
    ASSERT_NE(session, nullptr);

    EXPECT_EQ(session->BeginConfig(), CAMERA_OK);
    sptr<ICameraDeviceService> device = input->GetCameraDevice();
    EXPECT_EQ(session->AddInput(device), CAMERA_OK);

    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    sptr<IBufferProducer> producer = surface->GetProducer();

    sptr<HStreamRepeat> streamNullptr = new (std::nothrow) HStreamRepeat(nullptr, DEFAULT_FORMAT,
        DEFAULT_WIDTH, DEFAULT_HEIGHT, RepeatStreamType::PREVIEW);
    ASSERT_NE(streamNullptr, nullptr);
    sptr<HStreamRepeat> streamRepeat = new (std::nothrow) HStreamRepeat(producer, DEFAULT_FORMAT,
        DEFAULT_WIDTH, DEFAULT_HEIGHT, RepeatStreamType::PREVIEW);
    ASSERT_NE(streamRepeat, nullptr);
    sptr<HStreamRepeat> streamVideo = new (std::nothrow) HStreamRepeat(producer, DEFAULT_FORMAT,
        DEFAULT_WIDTH, DEFAULT_HEIGHT, RepeatStreamType::VIDEO);
    ASSERT_NE(streamVideo, nullptr);

    EXPECT_EQ(session->AddOutput(StreamType::REPEAT, streamNullptr), CAMERA_OK);
    EXPECT_EQ(session->AddOutput(StreamType::REPEAT, streamRepeat), CAMERA_OK);
    EXPECT_EQ(session->AddOutput(StreamType::REPEAT, streamVideo), CAMERA_OK);
    session->CommitConfig();
    session->Start();

    int32_t status = 0;
    session->GetOutputStatus(status);
    EXPECT_EQ(status, 0);

    session->Stop();
    EXPECT_EQ(input->Close(), CAMERA_OK);
    EXPECT_EQ(session->Release(), CAMERA_OK);
    session = nullptr;

    MEDIA_INFO_LOG("hcapture_session_unit_test_012 end");
}

/*
 * Feature: HCaptureSession
 * Function: Create media library for moving photo callback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test create media library with CameraPhotoProxy object for moving photo callback
 */
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_013, TestSize.Level0)
{
    MEDIA_INFO_LOG("hcapture_session_unit_test_013 start");

    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCaptureSession> session = new (std::nothrow) HCaptureSession(callerToken, SceneMode::NORMAL);
    ASSERT_NE(session, nullptr);

    sptr<CameraPhotoProxy> photoProxy{new CameraPhotoProxy()};
    std::string uri;
    int32_t cameraShotType;
    string burstKey = "";
    int64_t timestamp = 0000;
    int32_t captureId = 1;
    session->CreateMediaLibrary(photoProxy, uri, cameraShotType, burstKey, timestamp, captureId);

    EXPECT_EQ(session->Release(), CAMERA_OK);
    session = nullptr;

    MEDIA_INFO_LOG("hcapture_session_unit_test_013 end");
}

/*
 * Feature: HCaptureSession
 * Function: Create media library for moving photo callback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test create media library with Picture and CameraPhotoProxy object for moving photo callback
 */
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_014, TestSize.Level0)
{
    MEDIA_INFO_LOG("hcapture_session_unit_test_014 start");

    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCaptureSession> session = new (std::nothrow) HCaptureSession(callerToken, SceneMode::NORMAL);
    ASSERT_NE(session, nullptr);

    sptr<SurfaceBuffer> surfaceBuffer;
    sptr<CameraPhotoProxy> photoProxy{new CameraPhotoProxy()};
    std::string uri;
    int32_t cameraShotType;
    string burstKey = "";
    int64_t timestamp = 0000;
    int32_t captureId = 1;
    session->CreateMediaLibrary(Media::Picture::Create(surfaceBuffer), photoProxy, uri, cameraShotType,
        burstKey, timestamp, captureId);

    EXPECT_EQ(session->Release(), CAMERA_OK);
    session = nullptr;

    MEDIA_INFO_LOG("hcapture_session_unit_test_014 end");
}

/*
 * Feature: HCaptureSession
 * Function: Test onCaptureStarted onCapatureEnd onCaptureError when stream is nullptr
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test onCaptureStarted when stream is nullptr
 */
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_015, TestSize.Level0)
{
    MEDIA_INFO_LOG("hcapture_session_unit_test_015 start");

    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCaptureSession> session = new (std::nothrow) HCaptureSession(callerToken, SceneMode::NORMAL);
    ASSERT_NE(session, nullptr);


    EXPECT_EQ(session->Release(), CAMERA_OK);
    session = nullptr;

    MEDIA_INFO_LOG("hcapture_session_unit_test_015 end");
}

/*
 * Feature: HCaptureSession
 * Function: Test OnDrainImage and OnDrainImageFinish
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test OnDrainImage and OnDrainImageFinish
 */
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_016, TestSize.Level0)
{
    MEDIA_INFO_LOG("hcapture_session_unit_test_016 start");

    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCaptureSession> session = new (std::nothrow) HCaptureSession(callerToken, SceneMode::NORMAL);
    ASSERT_NE(session, nullptr);


    EXPECT_EQ(session->Release(), CAMERA_OK);
    session = nullptr;

    MEDIA_INFO_LOG("hcapture_session_unit_test_016 end");
}

} // namespace CameraStandard
} // namespace OHOS
