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

#include "access_token.h"
#include "accesstoken_kit.h"
#include "camera_log.h"
#include "camera_util.h"
#include "capture_session_callback_stub.h"
#include "gmock/gmock.h"
#include "hap_token_info.h"
#include "hcapture_session_unittest.h"
#include "icapture_session_callback.h"
#include "ipc_skeleton.h"
#include "metadata_utils.h"
#include "nativetoken_kit.h"
#include "os_account_manager.h"
#include "picture_interface.h"
#include "surface.h"
#include "test_common.h"
#include "test_token.h"
#include "token_setproc.h"
#include "camera_server_photo_proxy.h"

using namespace testing::ext;
using ::testing::Return;
using ::testing::_;

namespace OHOS {
namespace CameraStandard {
using namespace OHOS::HDI::Camera::V1_1;
using OHOS::HDI::Camera::V1_3::OperationMode;
constexpr static int32_t INTERFACE_CODE = 7;
constexpr static int32_t DEFAULT_WIDTH = 1280;
constexpr static int32_t DEFAULT_HEIGHT = 960;
constexpr static int32_t INVALID_WIDTH = 0;
constexpr static int32_t INVALID_HEIGHT = 0;
constexpr static int32_t DEFAULT_FORMAT = 4;
constexpr static uint32_t CAMERA_CAPTURE_SESSION_ON_DEFAULT = 1;
constexpr int32_t WIDE_CAMERA_ZOOM_RANGE = 0;
constexpr int32_t MAIN_CAMERA_ZOOM_RANGE = 1;
constexpr int32_t TWO_X_EXIT_TELE_ZOOM_RANGE = 2;
constexpr int32_t TELE_CAMERA_ZOOM_RANGE = 3;
static const std::string TEST_BUNDLE_NAME = "ohos";

void HCaptureSessionUnitTest::SetUpTestCase(void)
{
    ASSERT_TRUE(TestToken::GetAllCameraPermission());
}

void HCaptureSessionUnitTest::TearDownTestCase(void) {}

void HCaptureSessionUnitTest::SetUp()
{
    cameraHostManager_ = new HCameraHostManager(nullptr);
    cameraService_ = new HCameraService(cameraHostManager_);
    cameraManager_ = CameraManager::GetInstance();
}

void HCaptureSessionUnitTest::TearDown()
{
    if (cameraHostManager_) {
        cameraHostManager_ = nullptr;
    }
    if (cameraService_) {
        cameraService_ = nullptr;
    }
    if (cameraManager_) {
        cameraManager_ = nullptr;
    }
}

void HCaptureSessionUnitTest::InitSessionAndOperator(uint32_t callerToken, int32_t opMode,
    sptr<HCaptureSession>&  session, sptr<HStreamOperator>&  hStreamOperator)
{
    session = new (std::nothrow) HCaptureSession(callerToken, opMode);
    hStreamOperator = session->GetStreamOperator();
}

class MockHCaptureSessionCallbackStub : public CaptureSessionCallbackStub {
public:
    MOCK_METHOD1(OnError, int32_t(int32_t errorCode));
    ~MockHCaptureSessionCallbackStub() {}
};

class MockHPressureStatusCallbackStub : public PressureStatusCallbackStub {
public:
    MOCK_METHOD1(OnPressureStatusChanged,int32_t(PressureStatus status));
    ~MockHPressureStatusCallbackStub() {}
};
/*
 * Feature: HCaptureSession
 * Function: Test current stream infos are not empty after config normal streams
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test current stream infos are not empty after config normal streams
 */
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_001, TestSize.Level1)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    sptr<ICameraDeviceService> device = nullptr;
    cameraService_->CreateCameraDevice(cameraIds[0], device);
    ASSERT_NE(device, nullptr);
    EXPECT_EQ(device->Open(), CAMERA_OK);

    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCaptureSession> session = nullptr;
    sptr<HStreamOperator> hStreamOperator = nullptr;
    int32_t opMode = SceneMode::NORMAL;
    InitSessionAndOperator(callerToken, opMode, session, hStreamOperator);
    ASSERT_NE(session, nullptr);

    EXPECT_EQ(session->BeginConfig(), CAMERA_OK);
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
    EXPECT_EQ(device->Close(), CAMERA_OK);
    EXPECT_EQ(session->Release(), CAMERA_OK);
}

/*
 * Feature: HCaptureSession
 * Function: Test multiple add camera device
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test multiple add camera device, CanAddInput interface is not supported,
 * and commit comfig return camera invalid session cfg
 */
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_002, TestSize.Level1)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    sptr<ICameraDeviceService> device = nullptr;
    cameraService_->CreateCameraDevice(cameraIds[0], device);
    ASSERT_NE(device, nullptr);
    device->Open();

    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCaptureSession> session = nullptr;
    sptr<HStreamOperator> hStreamOperator = nullptr;
    int32_t opMode = SceneMode::NORMAL;
    InitSessionAndOperator(callerToken, opMode, session, hStreamOperator);
    ASSERT_NE(session, nullptr);

    bool result = false;
    EXPECT_EQ(session->BeginConfig(), CAMERA_OK);
    EXPECT_EQ(session->CanAddInput(device, result), CAMERA_OK);
    ASSERT_TRUE(result);
    EXPECT_EQ(session->AddInput(device), CAMERA_OK);

    EXPECT_EQ(session->CanAddInput(device, result), CAMERA_INVALID_SESSION_CFG);
    ASSERT_TRUE(!result);
    EXPECT_EQ(session->AddInput(device), CAMERA_INVALID_SESSION_CFG);
    EXPECT_EQ(session->CommitConfig(), CAMERA_INVALID_SESSION_CFG);

    EXPECT_EQ(device->Close(), CAMERA_OK);
    EXPECT_EQ(session->Release(), CAMERA_OK);
}

/*
 * Feature: HCaptureSession
 * Function: Test enable preview stream rotation when add output
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test need set preview rotation, preview stream can register display listener and
 * enable preview rotation when add output
 */
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_003, TestSize.Level1)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    sptr<ICameraDeviceService> device = nullptr;
    cameraService_->CreateCameraDevice(cameraIds[0], device);
    ASSERT_NE(device, nullptr);
    device->Open();

    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCaptureSession> session = nullptr;
    sptr<HStreamOperator> hStreamOperator = nullptr;
    int32_t opMode = SceneMode::NORMAL;
    InitSessionAndOperator(callerToken, opMode, session, hStreamOperator);
    ASSERT_NE(session, nullptr);

    EXPECT_EQ(session->BeginConfig(), CAMERA_OK);
    EXPECT_EQ(session->AddInput(device), CAMERA_OK);

    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    sptr<IBufferProducer> producer = surface->GetProducer();
    sptr<HStreamRepeat> streamRepeat = new (std::nothrow) HStreamRepeat(producer, DEFAULT_FORMAT,
        DEFAULT_WIDTH, DEFAULT_HEIGHT, RepeatStreamType::PREVIEW);
    ASSERT_NE(streamRepeat, nullptr);
    sptr<HStreamRepeat> videoRepeat = new (std::nothrow) HStreamRepeat(producer, DEFAULT_FORMAT,
        DEFAULT_WIDTH, DEFAULT_HEIGHT, RepeatStreamType::VIDEO);
    ASSERT_NE(videoRepeat, nullptr);

    EXPECT_EQ(session->AddOutput(StreamType::REPEAT, streamRepeat), CAMERA_OK);
    EXPECT_EQ(session->AddOutput(StreamType::REPEAT, videoRepeat), CAMERA_OK);
    EXPECT_EQ(session->RemoveOutput(StreamType::REPEAT, streamRepeat), CAMERA_OK);
    EXPECT_EQ(session->RemoveOutput(StreamType::REPEAT, videoRepeat), CAMERA_OK);

    std::string deviceClass{"device/0"};
    EXPECT_EQ(session->SetPreviewRotation(deviceClass), CAMERA_OK);
    EXPECT_EQ(session->AddOutput(StreamType::REPEAT, streamRepeat), CAMERA_OK);
    EXPECT_EQ(session->AddOutput(StreamType::REPEAT, videoRepeat), CAMERA_OK);
    EXPECT_EQ(session->RemoveOutput(StreamType::REPEAT, streamRepeat), CAMERA_OK);
    EXPECT_EQ(session->RemoveOutput(StreamType::REPEAT, videoRepeat), CAMERA_OK);

    EXPECT_EQ(session->CommitConfig(), CAMERA_INVALID_SESSION_CFG);

    EXPECT_EQ(device->Close(), CAMERA_OK);
    EXPECT_EQ(session->Release(), CAMERA_OK);
}

/*
 * Feature: HCaptureSession
 * Function: Test delete camera device after config normal stream
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test delete camera device after config normal stream, commit config return
 * camera invalid session cfg
 */
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_004, TestSize.Level1)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    sptr<ICameraDeviceService> device = nullptr;
    cameraService_->CreateCameraDevice(cameraIds[0], device);
    ASSERT_NE(device, nullptr);
    device->Open();
    EXPECT_EQ(device->Close(), CAMERA_OK);
}

/*
 * Feature: HCaptureSession
 * Function: Test secure camera when mode is secure but seqId is different
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test secure camera when mode is secure but seqId is different, commit config return
 * camera operator not allowed
 */
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_005, TestSize.Level1)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);

    for (auto cameraId : cameraIds) {
        sptr<ICameraDeviceService> device = nullptr;
        cameraService_->CreateCameraDevice(cameraId, device);
        ASSERT_NE(device, nullptr);

        shared_ptr<OHOS::Camera::CameraMetadata> cameraAbility;
        cameraHostManager_->GetCameraAbility(cameraId, cameraAbility);
        std::vector<OperationMode> supportedModes = {};
        camera_metadata_item_t item;
        int32_t retCode = OHOS::Camera::FindCameraMetadataItem(cameraAbility->get(), OHOS_ABILITY_CAMERA_MODES, &item);
        if (retCode == CAM_META_ITEM_NOT_FOUND) {
            GTEST_SKIP();
        }
        ASSERT_EQ(retCode, CAM_META_SUCCESS);
        ASSERT_NE(item.count, 0);

        for (uint32_t i = 0; i < item.count; i++) {
            supportedModes.emplace_back(static_cast<OperationMode>(item.data.u8[i]));
        }
        ASSERT_NE(supportedModes.size(), 0);
        if (find(supportedModes.begin(), supportedModes.end(), OperationMode::SECURE) != supportedModes.end()) {
            uint64_t secureSeqId = 1;
            device->OpenSecureCamera(secureSeqId);

            uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
            sptr<HCaptureSession> session = nullptr;
            sptr<HStreamOperator> hStreamOperator = nullptr;
            int32_t opMode = SceneMode::NORMAL;
            InitSessionAndOperator(callerToken, opMode, session, hStreamOperator);
            ASSERT_NE(session, nullptr);

            sptr<IConsumerSurface> surface = IConsumerSurface::Create();
            sptr<IBufferProducer> producer = surface->GetProducer();
            sptr<HStreamRepeat> streamRepeat = new (std::nothrow) HStreamRepeat(producer, DEFAULT_FORMAT,
                DEFAULT_WIDTH, DEFAULT_HEIGHT, RepeatStreamType::PREVIEW);
            ASSERT_NE(streamRepeat, nullptr);

            EXPECT_EQ(session->BeginConfig(), CAMERA_OK);
            EXPECT_EQ(session->AddInput(device), CAMERA_OK);
            EXPECT_EQ(session->AddOutput(StreamType::REPEAT, streamRepeat), CAMERA_OK);
            session->CommitConfig();

            EXPECT_EQ(device->Close(), CAMERA_OK);
            EXPECT_EQ(session->Release(), CAMERA_OK);
        }
    }
}

/*
 * Feature: HCaptureSession
 * Function: Test set color space interface, when color space format not match and need update
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * Function: Test set color space interface, when color space format not match and need update,
 * result return camera operator not allowed
 */
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_006, TestSize.Level1)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    sptr<ICameraDeviceService> device = nullptr;
    cameraService_->CreateCameraDevice(cameraIds[0], device);
    ASSERT_NE(device, nullptr);
    device->Open();

    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCaptureSession> session = nullptr;
    sptr<HStreamOperator> hStreamOperator = nullptr;
    int32_t opMode = SceneMode::NORMAL;
    InitSessionAndOperator(callerToken, opMode, session, hStreamOperator);
    ASSERT_NE(session, nullptr);

    EXPECT_EQ(session->BeginConfig(), CAMERA_OK);
    EXPECT_EQ(session->AddInput(device), CAMERA_OK);

    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    sptr<IBufferProducer> producer = surface->GetProducer();
    sptr<HStreamRepeat> streamRepeat = new (std::nothrow) HStreamRepeat(producer, DEFAULT_FORMAT,
        DEFAULT_WIDTH, DEFAULT_HEIGHT, RepeatStreamType::PREVIEW);
    ASSERT_NE(streamRepeat, nullptr);
    EXPECT_EQ(session->AddOutput(StreamType::REPEAT, streamRepeat), CAMERA_OK);
    session->CommitConfig();

    EXPECT_EQ(session->SetColorSpace(ColorSpace::BT2020_HLG, true), CAMERA_OPERATION_NOT_ALLOWED);

    EXPECT_EQ(device->Close(), CAMERA_OK);
    EXPECT_EQ(session->Release(), CAMERA_OK);
}

/*
 * Feature: HCaptureSession
 * Function: Test cancel stream and get stream infos with capture session
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test cancel stream and get stream infos with capture session configure preview stream,
 * metadata stream and capture stream in the context of session start and session stop
 */
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_007, TestSize.Level1)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    sptr<ICameraDeviceService> device = nullptr;
    cameraService_->CreateCameraDevice(cameraIds[0], device);
    ASSERT_NE(device, nullptr);
    device->Open();

    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCaptureSession> session = nullptr;
    sptr<HStreamOperator> hStreamOperator = nullptr;
    int32_t opMode = SceneMode::NORMAL;
    InitSessionAndOperator(callerToken, opMode, session, hStreamOperator);
    ASSERT_NE(session, nullptr);
    ASSERT_NE(hStreamOperator, nullptr);

    EXPECT_EQ(session->BeginConfig(), CAMERA_OK);
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
    std::vector<StreamInfo_V1_1> streamInfos = {};

    session->Start();
    hStreamOperator->CancelStreamsAndGetStreamInfos(streamInfos);
    ASSERT_TRUE(streamInfos.size() != 0);

    session->Stop();
    hStreamOperator->CancelStreamsAndGetStreamInfos(streamInfos);
    ASSERT_TRUE(streamInfos.size() != 0);

    EXPECT_EQ(device->Close(), CAMERA_OK);
    EXPECT_EQ(session->Release(), CAMERA_OK);
}

/*
 * Feature: HCaptureSession
 * Function: Test in the case of EnableMovingPhoto, live photo stream can start, preview and null streams can not
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test in the case of EnableMovingPhoto, live photo stream can start, preview and null streams can not
 */
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_008, TestSize.Level1)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    sptr<ICameraDeviceService> device = nullptr;
    cameraService_->CreateCameraDevice(cameraIds[0], device);
    ASSERT_NE(device, nullptr);
    device->Open();

    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCaptureSession> session = nullptr;
    sptr<HStreamOperator> hStreamOperator = nullptr;
    int32_t opMode = SceneMode::NORMAL;
    InitSessionAndOperator(callerToken, opMode, session, hStreamOperator);
    ASSERT_NE(session, nullptr);
    ASSERT_NE(hStreamOperator, nullptr);

    EXPECT_EQ(session->BeginConfig(), CAMERA_OK);
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

    shared_ptr<OHOS::Camera::CameraMetadata> settings;
    cameraHostManager_->GetCameraAbility(cameraIds[0], settings);
    hStreamOperator->StartMovingPhoto(settings, streamRepeat2);

    EXPECT_EQ(session->EnableMovingPhoto(false), CAMERA_OK);
    session->Start();

    session->Stop();
    EXPECT_EQ(device->Close(), CAMERA_OK);
    EXPECT_EQ(session->Release(), CAMERA_OK);
}

/*
 * Feature: HCaptureSession
 * Function: Test operate permission check, when interfaceCode unequal calling token id
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * Function: Test operate permission check, when interfaceCode unequal calling token id
 */
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_009, TestSize.Level1)
{
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    uint32_t callerToken1 = ++callerToken;
    sptr<HCaptureSession> session = nullptr;
    sptr<HStreamOperator> hStreamOperator = nullptr;
    int32_t opMode = SceneMode::NORMAL;
    InitSessionAndOperator(callerToken1, opMode, session, hStreamOperator);
    ASSERT_NE(session, nullptr);

    EXPECT_EQ(session->OperatePermissionCheck(INTERFACE_CODE), CAMERA_OPERATION_NOT_ALLOWED);
    EXPECT_EQ(session->Release(), CAMERA_OK);
}

/*
 * Feature: HCaptureSession
 * Function: Test capture session get pid and destory stub object by pid
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test capture session get pid and destory stub object by pid
 */
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_010, TestSize.Level1)
{
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCaptureSession> session = nullptr;
    sptr<HStreamOperator> hStreamOperator = nullptr;
    int32_t opMode = SceneMode::NORMAL;
    InitSessionAndOperator(callerToken, opMode, session, hStreamOperator);
    ASSERT_NE(session, nullptr);

    pid_t pid = session->GetPid();
    session->DestroyStubObjectForPid(pid);
}

/*
 * Feature: HCaptureSession
 * Function: Test dump session info with capture session configure preview stream and photo stream
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test dump session info with capture session configure preview stream and photo stream
 */
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_011, TestSize.Level1)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    sptr<ICameraDeviceService> device = nullptr;
    cameraService_->CreateCameraDevice(cameraIds[0], device);
    ASSERT_NE(device, nullptr);
    device->Open();

    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCaptureSession> session = nullptr;
    sptr<HStreamOperator> hStreamOperator = nullptr;
    int32_t opMode = SceneMode::NORMAL;
    InitSessionAndOperator(callerToken, opMode, session, hStreamOperator);
    ASSERT_NE(session, nullptr);

    EXPECT_EQ(session->BeginConfig(), CAMERA_OK);
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
    EXPECT_EQ(device->Close(), CAMERA_OK);
    EXPECT_EQ(session->Release(), CAMERA_OK);
}

/*
 * Feature: HCaptureSession
 * Function: Test get output status with capture session configure null capture, normal preview  and video stream
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test get output status with capture session configure null capture, normal preview and video stream
 */
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_012, TestSize.Level1)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    sptr<ICameraDeviceService> device = nullptr;
    cameraService_->CreateCameraDevice(cameraIds[0], device);
    ASSERT_NE(device, nullptr);
    device->Open();

    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCaptureSession> session = nullptr;
    sptr<HStreamOperator> hStreamOperator = nullptr;
    int32_t opMode = SceneMode::NORMAL;
    InitSessionAndOperator(callerToken, opMode, session, hStreamOperator);
    ASSERT_NE(session, nullptr);

    EXPECT_EQ(session->BeginConfig(), CAMERA_OK);
    EXPECT_EQ(session->AddInput(device), CAMERA_OK);

    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    sptr<IBufferProducer> producer = surface->GetProducer();

    sptr<HStreamRepeat> streamRepeat = new (std::nothrow) HStreamRepeat(producer, DEFAULT_FORMAT,
        DEFAULT_WIDTH, DEFAULT_HEIGHT, RepeatStreamType::PREVIEW);
    ASSERT_NE(streamRepeat, nullptr);
    sptr<HStreamRepeat> streamVideo = new (std::nothrow) HStreamRepeat(producer, DEFAULT_FORMAT,
        DEFAULT_WIDTH, DEFAULT_HEIGHT, RepeatStreamType::VIDEO);
    ASSERT_NE(streamVideo, nullptr);
    sptr<HStreamCapture> streamCapture = new (std::nothrow) HStreamCapture(producer, DEFAULT_FORMAT,
        DEFAULT_WIDTH, DEFAULT_HEIGHT);
    ASSERT_NE(streamCapture, nullptr);

    EXPECT_EQ(session->AddOutput(StreamType::REPEAT, streamRepeat), CAMERA_OK);
    EXPECT_EQ(session->AddOutput(StreamType::REPEAT, streamVideo), CAMERA_OK);
    EXPECT_EQ(session->AddOutput(StreamType::CAPTURE, streamCapture), CAMERA_OK);
    session->CommitConfig();
    session->Start();

    streamVideo->Start();
    int32_t status = 0;
    session->GetOutputStatus(status);

    streamVideo->Stop();
    int32_t otherStatus = 0;
    session->GetOutputStatus(otherStatus);

    session->Stop();
    EXPECT_EQ(device->Close(), CAMERA_OK);
    EXPECT_EQ(session->Release(), CAMERA_OK);
}

/*
 * Feature: HCaptureSession
 * Function: Create media library for moving photo callback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test create media library with CameraPhotoProxy object for moving photo callback
 */
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_013, TestSize.Level1)
{
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCaptureSession> session = nullptr;
    sptr<HStreamOperator> hStreamOperator = nullptr;
    int32_t opMode = SceneMode::NORMAL;
    InitSessionAndOperator(callerToken, opMode, session, hStreamOperator);
    ASSERT_NE(session, nullptr);
    ASSERT_NE(hStreamOperator, nullptr);

    sptr<CameraServerPhotoProxy> photoProxy{new CameraServerPhotoProxy()};
    std::string uri;
    int32_t cameraShotType;
    string burstKey = "";
    int64_t timestamp = 0000;
    hStreamOperator->CreateMediaLibrary(photoProxy, uri, cameraShotType, burstKey, timestamp);

    EXPECT_EQ(session->Release(), CAMERA_OK);
}

/*
 * Feature: HCaptureSession
 * Function: Create media library for moving photo callback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test create media library with Picture and CameraPhotoProxy object for moving photo callback
 */
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_014, TestSize.Level1)
{
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCaptureSession> session = nullptr;
    sptr<HStreamOperator> hStreamOperator = nullptr;
    int32_t opMode = SceneMode::NORMAL;
    InitSessionAndOperator(callerToken, opMode, session, hStreamOperator);
    ASSERT_NE(session, nullptr);
    ASSERT_NE(hStreamOperator, nullptr);

    sptr<SurfaceBuffer> surfaceBuffer = SurfaceBuffer::Create();
    sptr<CameraServerPhotoProxy> photoProxy{new CameraServerPhotoProxy()};
    std::string uri;
    int32_t cameraShotType;
    string burstKey = "";
    int64_t timestamp = 0000;
    auto picture = GetPictureIntfInstance();
    picture->Create(surfaceBuffer);
    hStreamOperator->CreateMediaLibrary(picture, photoProxy, uri, cameraShotType,
        burstKey, timestamp);

    EXPECT_EQ(session->Release(), CAMERA_OK);
}

/*
 * Feature: HCaptureSession
 * Function: Test onCaptureStarted and OnCaptureStarted_V1_2 when GetHdiStreamByStreamID is null
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test onCaptureStarted and OnCaptureStarted_V1_2 when GetHdiStreamByStreamID is null
 */
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_015, TestSize.Level1)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    sptr<ICameraDeviceService> device = nullptr;
    cameraService_->CreateCameraDevice(cameraIds[0], device);
    ASSERT_NE(device, nullptr);
    device->Open();

    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCaptureSession> session = nullptr;
    sptr<HStreamOperator> hStreamOperator = nullptr;
    int32_t opMode = SceneMode::NORMAL;
    InitSessionAndOperator(callerToken, opMode, session, hStreamOperator);
    ASSERT_NE(session, nullptr);
    ASSERT_NE(hStreamOperator, nullptr);

    session->BeginConfig();
    EXPECT_EQ(session->AddInput(device), CAMERA_OK);

    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    sptr<IBufferProducer> producer = surface->GetProducer();

    sptr<HStreamRepeat> streamRepeat = new (std::nothrow) HStreamRepeat(producer, DEFAULT_FORMAT,
        DEFAULT_WIDTH, DEFAULT_HEIGHT, RepeatStreamType::PREVIEW);
    ASSERT_NE(streamRepeat, nullptr);
    EXPECT_EQ(session->AddOutput(StreamType::REPEAT, streamRepeat), CAMERA_OK);
    session->CommitConfig();

    int32_t captureId = 0;
    std::vector<int32_t> streamIds = {1, 2};
    EXPECT_EQ(hStreamOperator->OnCaptureStarted(captureId, streamIds), CAMERA_INVALID_ARG);

    HDI::Camera::V1_2::CaptureStartedInfo it1;
    it1.streamId_ = 1;
    it1.exposureTime_ = 1;
    HDI::Camera::V1_2::CaptureStartedInfo it2;
    it2.streamId_ = 2;
    it2.exposureTime_ = 2;
    std::vector<OHOS::HDI::Camera::V1_2::CaptureStartedInfo> captureStartedInfo = {};
    captureStartedInfo.push_back(it1);
    captureStartedInfo.push_back(it2);
    EXPECT_EQ(hStreamOperator->OnCaptureStarted_V1_2(captureId, captureStartedInfo), CAMERA_INVALID_ARG);

    EXPECT_EQ(device->Close(), CAMERA_OK);
    EXPECT_EQ(session->Release(), CAMERA_OK);
}

/*
 * Feature: HCaptureSession
 * Function: Test OnCaptureEnded and OnCaptureEndedExt when GetHdiStreamByStreamID is null
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test OnCaptureEnded and OnCaptureEndedExt when GetHdiStreamByStreamID is null
 */
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_016, TestSize.Level1)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    sptr<ICameraDeviceService> device = nullptr;
    cameraService_->CreateCameraDevice(cameraIds[0], device);
    ASSERT_NE(device, nullptr);
    device->Open();

    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCaptureSession> session = nullptr;
    sptr<HStreamOperator> hStreamOperator = nullptr;
    int32_t opMode = SceneMode::NORMAL;
    InitSessionAndOperator(callerToken, opMode, session, hStreamOperator);
    ASSERT_NE(session, nullptr);
    ASSERT_NE(hStreamOperator, nullptr);

    session->BeginConfig();
    EXPECT_EQ(session->AddInput(device), CAMERA_OK);

    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    sptr<IBufferProducer> producer = surface->GetProducer();

    sptr<HStreamRepeat> streamRepeat = new (std::nothrow) HStreamRepeat(producer, DEFAULT_FORMAT,
        DEFAULT_WIDTH, DEFAULT_HEIGHT, RepeatStreamType::PREVIEW);
    ASSERT_NE(streamRepeat, nullptr);
    EXPECT_EQ(session->AddOutput(StreamType::REPEAT, streamRepeat), CAMERA_OK);
    session->CommitConfig();

    int32_t captureId = 0;
    std::vector<OHOS::HDI::Camera::V1_3::CaptureEndedInfoExt> infos = {{1, 100, true, "video123"},
        {2, 100, true, "video123"}};
    EXPECT_EQ(hStreamOperator->OnCaptureEndedExt(captureId, infos), CAMERA_INVALID_ARG);

    EXPECT_EQ(device->Close(), CAMERA_OK);
    EXPECT_EQ(session->Release(), CAMERA_OK);
}

/*
 * Feature: HCaptureSession
 * Function: Test OnCaptureError when stream type is repeat or capture
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test OnCaptureError when stream type is repeat or capture
 */
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_017, TestSize.Level1)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    sptr<ICameraDeviceService> device = nullptr;
    cameraService_->CreateCameraDevice(cameraIds[0], device);
    ASSERT_NE(device, nullptr);
    device->Open();

    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCaptureSession> session = nullptr;
    sptr<HStreamOperator> hStreamOperator = nullptr;
    int32_t opMode = SceneMode::NORMAL;
    InitSessionAndOperator(callerToken, opMode, session, hStreamOperator);
    ASSERT_NE(session, nullptr);
    ASSERT_NE(hStreamOperator, nullptr);

    EXPECT_EQ(session->BeginConfig(), CAMERA_OK);
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

    int32_t captureId = 0;
    CaptureErrorInfo it1;
    it1.streamId_ = 2;
    it1.error_ = BUFFER_LOST;
    CaptureErrorInfo it2;
    it2.streamId_ = 1;
    it2.error_ = BUFFER_LOST;
    std::vector<CaptureErrorInfo> captureErrorInfo = {};
    captureErrorInfo.push_back(it1);
    captureErrorInfo.push_back(it2);
    hStreamOperator->OnCaptureError(captureId, captureErrorInfo);

    EXPECT_EQ(device->Close(), CAMERA_OK);
    EXPECT_EQ(session->Release(), CAMERA_OK);
}

/*
 * Feature: HCaptureSession
 * Function: Test OnResult when stream type is not metadata, session return camera invalid arg
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test OnResult when stream type is not metadata, session return camera invalid arg
 */
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_018, TestSize.Level1)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    sptr<ICameraDeviceService> device = nullptr;
    cameraService_->CreateCameraDevice(cameraIds[0], device);
    ASSERT_NE(device, nullptr);
    device->Open();

    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCaptureSession> session = nullptr;
    sptr<HStreamOperator> hStreamOperator = nullptr;
    int32_t opMode = SceneMode::NORMAL;
    InitSessionAndOperator(callerToken, opMode, session, hStreamOperator);
    ASSERT_NE(session, nullptr);
    ASSERT_NE(hStreamOperator, nullptr);

    EXPECT_EQ(session->BeginConfig(), CAMERA_OK);
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

    int32_t streamId = 1;
    std::vector<uint8_t> result = {0, 1};
    EXPECT_EQ(hStreamOperator->OnResult(streamId, result), CAMERA_INVALID_ARG);
    streamId = 2;
    EXPECT_EQ(hStreamOperator->OnResult(streamId, result), CAMERA_INVALID_ARG);

    EXPECT_EQ(device->Close(), CAMERA_OK);
    EXPECT_EQ(session->Release(), CAMERA_OK);
}

/*
 * Feature: HCaptureSession
 * Function: Test AddStream when stream exists already, add same stream fail
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test AddStream when stream exists already, add same stream fail
 */
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_019, TestSize.Level1)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    sptr<ICameraDeviceService> device = nullptr;
    cameraService_->CreateCameraDevice(cameraIds[0], device);
    ASSERT_NE(device, nullptr);
    device->Open();

    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCaptureSession> session = nullptr;
    sptr<HStreamOperator> hStreamOperator = nullptr;
    int32_t opMode = SceneMode::NORMAL;
    InitSessionAndOperator(callerToken, opMode, session, hStreamOperator);
    ASSERT_NE(session, nullptr);

    EXPECT_EQ(session->BeginConfig(), CAMERA_OK);
    EXPECT_EQ(session->AddInput(device), CAMERA_OK);

    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    sptr<IBufferProducer> producer = surface->GetProducer();

    sptr<HStreamRepeat> streamRepeat = new (std::nothrow) HStreamRepeat(producer, DEFAULT_FORMAT,
        DEFAULT_WIDTH, DEFAULT_HEIGHT, RepeatStreamType::PREVIEW);
    ASSERT_NE(streamRepeat, nullptr);

    EXPECT_EQ(session->AddOutput(StreamType::REPEAT, streamRepeat), CAMERA_OK);
    EXPECT_EQ(session->AddOutput(StreamType::REPEAT, streamRepeat), CAMERA_INVALID_SESSION_CFG);
    session->CommitConfig();

    EXPECT_EQ(device->Close(), CAMERA_OK);
    EXPECT_EQ(session->Release(), CAMERA_OK);
}

/*
 * Feature: HCaptureSession
 * Function: Test add input output, when session state is not in-progress, return camera invalid state
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test add input output, when session state is not in-progress, return camera invalid state
 */
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_020, TestSize.Level1)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    sptr<ICameraDeviceService> device = nullptr;
    cameraService_->CreateCameraDevice(cameraIds[0], device);
    ASSERT_NE(device, nullptr);
    device->Open();

    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCaptureSession> session = nullptr;
    sptr<HStreamOperator> hStreamOperator = nullptr;
    int32_t opMode = SceneMode::NORMAL;
    InitSessionAndOperator(callerToken, opMode, session, hStreamOperator);
    ASSERT_NE(session, nullptr);

    bool result = false;
    EXPECT_EQ(session->CanAddInput(device, result), CAMERA_INVALID_STATE);
    ASSERT_TRUE(!result);

    EXPECT_EQ(session->BeginConfig(), CAMERA_OK);
    EXPECT_EQ(session->CanAddInput(device, result), CAMERA_OK);
    ASSERT_TRUE(result);
    EXPECT_EQ(session->AddInput(device), CAMERA_OK);
    session->CommitConfig();

    EXPECT_EQ(device->Close(), CAMERA_OK);
    EXPECT_EQ(session->Release(), CAMERA_OK);
}

/*
 * Feature: HCaptureSession
 * Function: Test AddOutputStream and RemoveOutput when stream type is metadata or depthdata,
 * various situations covering parameters
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test AddOutputStream and RemoveOutput when stream type is metadata or depthdata,
 * various situations covering parameters
 */
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_021, TestSize.Level1)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    sptr<ICameraDeviceService> device = nullptr;
    cameraService_->CreateCameraDevice(cameraIds[0], device);
    ASSERT_NE(device, nullptr);
    device->Open();

    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCaptureSession> session = nullptr;
    sptr<HStreamOperator> hStreamOperator = nullptr;
    int32_t opMode = SceneMode::NORMAL;
    InitSessionAndOperator(callerToken, opMode, session, hStreamOperator);
    ASSERT_NE(session, nullptr);
    ASSERT_NE(hStreamOperator, nullptr);

    EXPECT_EQ(session->BeginConfig(), CAMERA_OK);
    EXPECT_EQ(session->AddInput(device), CAMERA_OK);

    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    sptr<IBufferProducer> producer = surface->GetProducer();
    sptr<HStreamRepeat> streamRepeat = new (std::nothrow) HStreamRepeat(producer, DEFAULT_FORMAT,
        DEFAULT_WIDTH, DEFAULT_HEIGHT, RepeatStreamType::PREVIEW);
    ASSERT_NE(streamRepeat, nullptr);
    sptr<HStreamMetadata> streamMetadata= new(std::nothrow) HStreamMetadata(producer, 0, {1});
    ASSERT_NE(streamMetadata, nullptr);

    EXPECT_EQ(session->AddOutput(StreamType::METADATA, streamMetadata), CAMERA_OK);
    EXPECT_EQ(session->AddOutput(StreamType::METADATA, streamMetadata), CAMERA_INVALID_SESSION_CFG);
    EXPECT_EQ(session->RemoveOutput(StreamType::METADATA, streamMetadata), CAMERA_OK);
    EXPECT_EQ(session->CommitConfig(), CAMERA_INVALID_SESSION_CFG);

    EXPECT_EQ(hStreamOperator->AddOutputStream(nullptr), CAMERA_INVALID_ARG);
    EXPECT_EQ(hStreamOperator->AddOutputStream(streamMetadata), CAMERA_OK);
    EXPECT_EQ(hStreamOperator->AddOutputStream(streamMetadata), CAMERA_INVALID_SESSION_CFG);
    EXPECT_EQ(streamRepeat->Release(), CAMERA_OK);
    EXPECT_EQ(hStreamOperator->AddOutputStream(streamRepeat), CAMERA_INVALID_ARG);

    EXPECT_EQ(device->Close(), CAMERA_OK);
    EXPECT_EQ(session->Release(), CAMERA_OK);
}

/*
 * Feature: HCaptureSession
 * Function: Test UpdateStreamInfos when camera device in null, return camera unknown error
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test UpdateStreamInfos when camera device in null, return camera unknown error
 */
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_022, TestSize.Level1)
{
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCaptureSession> session = nullptr;
    sptr<HStreamOperator> hStreamOperator = nullptr;
    int32_t opMode = SceneMode::NORMAL;
    InitSessionAndOperator(callerToken, opMode, session, hStreamOperator);
    ASSERT_NE(session, nullptr);
    ASSERT_NE(hStreamOperator, nullptr);

    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    shared_ptr<OHOS::Camera::CameraMetadata> settings;
    cameraHostManager_->GetCameraAbility(cameraIds[0], settings);
    EXPECT_EQ(hStreamOperator->UpdateStreamInfos(settings), CAMERA_UNKNOWN_ERROR);
    EXPECT_EQ(session->Release(), CAMERA_OK);
}

/*
 * Feature: HCaptureSession
 * Function: Test session stop, when other stream undefined exists, other types of streams cannot be stopped
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test session stop, when other undefined stream exists, other types of streams cannot be stopped
 */
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_023, TestSize.Level1)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    sptr<ICameraDeviceService> device = nullptr;
    cameraService_->CreateCameraDevice(cameraIds[0], device);
    ASSERT_NE(device, nullptr);
    device->Open();

    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCaptureSession> session = nullptr;
    sptr<HStreamOperator> hStreamOperator = nullptr;
    int32_t opMode = SceneMode::NORMAL;
    InitSessionAndOperator(callerToken, opMode, session, hStreamOperator);
    ASSERT_NE(session, nullptr);

    EXPECT_EQ(session->BeginConfig(), CAMERA_OK);
    EXPECT_EQ(session->AddInput(device), CAMERA_OK);

    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    sptr<IBufferProducer> producer = surface->GetProducer();
    sptr<HStreamRepeat> streamRepeat = new (std::nothrow) HStreamRepeat(producer, DEFAULT_FORMAT,
        DEFAULT_WIDTH, DEFAULT_HEIGHT, RepeatStreamType::PREVIEW);
    ASSERT_NE(streamRepeat, nullptr);
    uint32_t otherStreamType = 5;
    streamRepeat->streamType_ = static_cast<StreamType>(otherStreamType);

    session->AddOutput(StreamType::REPEAT, streamRepeat);
    session->CommitConfig();
    session->Start();

    EXPECT_EQ(session->Stop(), CAMERA_OK);
    EXPECT_EQ(device->Close(), CAMERA_OK);
    EXPECT_EQ(session->Release(), CAMERA_OK);
}

/*
 * Feature: HCaptureSession
 * Function: Test get session state, when another capture session state exists, other state cannot be found
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * Function: Test get session state, when another capture session state exists, other state cannot be found
 */
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_024, TestSize.Level1)
{
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCaptureSession> session = nullptr;
    sptr<HStreamOperator> hStreamOperator = nullptr;
    int32_t opMode = SceneMode::NORMAL;
    InitSessionAndOperator(callerToken, opMode, session, hStreamOperator);
    ASSERT_NE(session, nullptr);

    uint32_t otherCaptureSessionState = 6;
    session->stateMachine_.currentState_ = static_cast<CaptureSessionState>(otherCaptureSessionState);
    EXPECT_EQ(session->GetSessionState(), std::to_string(otherCaptureSessionState));

    session->stateMachine_.currentState_ = CaptureSessionState::SESSION_INIT;
    EXPECT_EQ(session->GetSessionState(), "Init");
    EXPECT_EQ(session->Release(), CAMERA_OK);
}

/*
 * Feature: HCaptureSession
 * Function: Test EnableMovingPhotoMirror with preview stream and livephoto stream, interface call is normal
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test EnableMovingPhotoMirror with preview stream and livephoto stream, interface call is normal
 */
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_025, TestSize.Level1)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    sptr<ICameraDeviceService> device = nullptr;
    cameraService_->CreateCameraDevice(cameraIds[0], device);
    ASSERT_NE(device, nullptr);
    device->Open();

    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCaptureSession> session = nullptr;
    sptr<HStreamOperator> hStreamOperator = nullptr;
    int32_t opMode = SceneMode::NORMAL;
    InitSessionAndOperator(callerToken, opMode, session, hStreamOperator);
    ASSERT_NE(session, nullptr);

    EXPECT_EQ(session->BeginConfig(), CAMERA_OK);
    EXPECT_EQ(session->AddInput(device), CAMERA_OK);

    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    sptr<IBufferProducer> producer = surface->GetProducer();
    sptr<HStreamRepeat> streamRepeat = new (std::nothrow) HStreamRepeat(producer, DEFAULT_FORMAT,
        DEFAULT_WIDTH, DEFAULT_HEIGHT, RepeatStreamType::PREVIEW);
    ASSERT_NE(streamRepeat, nullptr);
    sptr<HStreamRepeat> livephotoRepeat = new (std::nothrow) HStreamRepeat(producer, DEFAULT_FORMAT,
        DEFAULT_WIDTH, DEFAULT_HEIGHT, RepeatStreamType::LIVEPHOTO);
    ASSERT_NE(livephotoRepeat, nullptr);

    EXPECT_EQ(session->AddOutput(StreamType::REPEAT, streamRepeat), CAMERA_OK);
    EXPECT_EQ(session->AddOutput(StreamType::REPEAT, livephotoRepeat), CAMERA_OK);
    session->CommitConfig();

    EXPECT_EQ(session->EnableMovingPhoto(true), CAMERA_OK);
    EXPECT_EQ(session->EnableMovingPhotoMirror(true, true), CAMERA_OK);

    session->Start();
    session->Stop();
    EXPECT_EQ(device->Close(), CAMERA_OK);
    EXPECT_EQ(session->Release(), CAMERA_OK);
}

/*
 * Feature: HCaptureSession
 * Function: Test ExpandSketchRepeatStream and ClearSketchRepeatStream with sketch stream
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * Function: Test ExpandSketchRepeatStream and ClearSketchRepeatStream with sketch stream,
 * when it exists, it is normally added to output streams
 */
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_026, TestSize.Level1)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    sptr<ICameraDeviceService> device = nullptr;
    cameraService_->CreateCameraDevice(cameraIds[0], device);
    ASSERT_NE(device, nullptr);
    device->Open();

    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCaptureSession> session = nullptr;
    sptr<HStreamOperator> hStreamOperator = nullptr;
    int32_t opMode = SceneMode::NORMAL;
    InitSessionAndOperator(callerToken, opMode, session, hStreamOperator);
    ASSERT_NE(session, nullptr);

    EXPECT_EQ(session->BeginConfig(), CAMERA_OK);
    EXPECT_EQ(session->AddInput(device), CAMERA_OK);

    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    sptr<IBufferProducer> producer = surface->GetProducer();
    sptr<HStreamRepeat> streamRepeat = new (std::nothrow) HStreamRepeat(producer, DEFAULT_FORMAT,
        DEFAULT_WIDTH, DEFAULT_HEIGHT, RepeatStreamType::PREVIEW);
    ASSERT_NE(streamRepeat, nullptr);
    sptr<HStreamRepeat> sketchRepeat = new (std::nothrow) HStreamRepeat(producer, DEFAULT_FORMAT,
        DEFAULT_WIDTH, DEFAULT_HEIGHT, RepeatStreamType::SKETCH);
    ASSERT_NE(sketchRepeat, nullptr);

    EXPECT_EQ(session->AddOutput(StreamType::REPEAT, streamRepeat), CAMERA_OK);
    EXPECT_EQ(session->AddOutput(StreamType::REPEAT, sketchRepeat), CAMERA_OK);
    session->CommitConfig();

    session->BeginConfig();
    EXPECT_EQ(session->Release(), CAMERA_OK);
}

/*
 * Feature: HCaptureSession
 * Function: Test ExpandMovingPhotoRepeatStream with CreateMovingPhotoSurfaceWrapper or CreateMovingPhotoStreamRepeat
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * Function: Test ExpandMovingPhotoRepeatStream, CreateMovingPhotoSurfaceWrapper when width or height is invalid,
 * and livePhotoStreamRepeat_ needs to be released and recreated when it is not null
 */
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_027, TestSize.Level1)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    sptr<ICameraDeviceService> device = nullptr;
    cameraService_->CreateCameraDevice(cameraIds[0], device);
    ASSERT_NE(device, nullptr);
    device->Open();

    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCaptureSession> session = nullptr;
    sptr<HStreamOperator> hStreamOperator = nullptr;
    int32_t opMode = SceneMode::NORMAL;
    InitSessionAndOperator(callerToken, opMode, session, hStreamOperator);
    ASSERT_NE(session, nullptr);

    EXPECT_EQ(session->BeginConfig(), CAMERA_OK);
    EXPECT_EQ(session->AddInput(device), CAMERA_OK);

    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    sptr<IBufferProducer> producer = surface->GetProducer();
    sptr<HStreamRepeat> streamRepeat = new (std::nothrow) HStreamRepeat(producer, DEFAULT_FORMAT,
        DEFAULT_WIDTH, DEFAULT_HEIGHT, RepeatStreamType::PREVIEW);
    ASSERT_NE(streamRepeat, nullptr);
    sptr<HStreamRepeat> streamRepeat1 = new (std::nothrow) HStreamRepeat(producer, DEFAULT_FORMAT,
        DEFAULT_WIDTH, DEFAULT_HEIGHT, RepeatStreamType::PREVIEW);
    ASSERT_NE(streamRepeat1, nullptr);
    sptr<HStreamRepeat> streamRepeat2 = new (std::nothrow) HStreamRepeat(producer, DEFAULT_FORMAT,
        INVALID_WIDTH, INVALID_HEIGHT, RepeatStreamType::PREVIEW);
    ASSERT_NE(streamRepeat2, nullptr);

    EXPECT_EQ(session->AddOutput(StreamType::REPEAT, streamRepeat), CAMERA_OK);
    EXPECT_EQ(session->AddOutput(StreamType::REPEAT, streamRepeat1), CAMERA_OK);
    EXPECT_EQ(session->AddOutput(StreamType::REPEAT, streamRepeat2), CAMERA_OK);
    session->CommitConfig();

    session->BeginConfig();
    EXPECT_EQ(device->Close(), CAMERA_OK);
    EXPECT_EQ(session->Release(), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test HCaptureSession with anomalous branch
 */
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_028, TestSize.Level1)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    sptr<ICameraDeviceService> device = nullptr;
    cameraService_->CreateCameraDevice(cameraIds[0], device);
    ASSERT_NE(device, nullptr);
    device->Open();

    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCaptureSession> camSession = nullptr;
    sptr<HStreamOperator> hStreamOperator = nullptr;
    SceneMode mode = PORTRAIT;
    InitSessionAndOperator(callerToken, mode, camSession, hStreamOperator);
    ASSERT_NE(camSession, nullptr);

    int32_t ret = camSession->AddInput(device);
    EXPECT_EQ(ret, 10);

    ret = camSession->RemoveInput(device);
    EXPECT_EQ(ret, 10);
    device->Close();
    ret = camSession->BeginConfig();
    EXPECT_EQ(ret, 0);

    ret = camSession->BeginConfig();
    EXPECT_EQ(ret, 10);

    device = nullptr;
    ret = camSession->AddInput(device);
    EXPECT_EQ(ret, 2);

    ret = camSession->RemoveInput(device);
    EXPECT_EQ(ret, 2);

    sptr<IRemoteObject> stream_2 = nullptr;
    ret = camSession->AddOutput(StreamType::CAPTURE, stream_2);
    EXPECT_EQ(ret, 2);

    ret = camSession->RemoveOutput(StreamType::CAPTURE, stream_2);
    EXPECT_EQ(ret, 2);

    camSession->Release();
}

/*
 * Feature: coverage
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test HCaptureSession with anomalous branch.
 */
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_029, TestSize.Level1)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    sptr<ICameraDeviceService> device = nullptr;
    cameraService_->CreateCameraDevice(cameraIds[0], device);
    ASSERT_NE(device, nullptr);
    device->Open();

    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCaptureSession> camSession = nullptr;
    sptr<HStreamOperator> hStreamOperator = nullptr;
    SceneMode mode = PORTRAIT;
    InitSessionAndOperator(callerToken, mode, camSession, hStreamOperator);
    ASSERT_NE(camSession, nullptr);
    ASSERT_NE(hStreamOperator, nullptr);

    camSession->BeginConfig();
    camSession->Start();

    sptr<IConsumerSurface> Surface = IConsumerSurface::Create();
    sptr<IBufferProducer> producer = Surface->GetProducer();

    auto streamRepeat = new (std::nothrow) HStreamRepeat(producer, 4, 1280, 960, RepeatStreamType::PREVIEW);
    ASSERT_NE(streamRepeat, nullptr);
    auto streamRepeat1 = new (std::nothrow) HStreamRepeat(producer, 3, 640, 480, RepeatStreamType::PREVIEW);
    ASSERT_NE(streamRepeat1, nullptr);
    sptr<HStreamCapture> streamCapture = new (std::nothrow) HStreamCapture(producer, 4, 1280, 960);
    ASSERT_NE(streamCapture, nullptr);

    EXPECT_EQ(camSession->AddOutput(StreamType::REPEAT, streamRepeat), 0);
    EXPECT_EQ(camSession->AddOutput(StreamType::REPEAT, streamRepeat1), 0);
    EXPECT_EQ(camSession->AddOutput(StreamType::CAPTURE, streamCapture), 0);

    CaptureErrorInfo it1;
    it1.streamId_ = 2;
    it1.error_ = BUFFER_LOST;
    CaptureErrorInfo it2;
    it2.streamId_ = 1;
    it2.error_ =  BUFFER_LOST;
    std::vector<CaptureErrorInfo> info = {};
    info.push_back(it1);
    info.push_back(it2);
    hStreamOperator->OnCaptureError(0, info);

    std::vector<int32_t> streamIds = {1, 2};
    hStreamOperator->OnFrameShutter(0, streamIds, 0);
    hStreamOperator->OnFrameShutterEnd(0, streamIds, 0);
    hStreamOperator->OnCaptureReady(0, streamIds, 0);
    device->Close();
    camSession->Release();
}

/*
 * Feature: coverage
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test HCaptureSession with anomalous branch.
 */
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_030, TestSize.Level1)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    sptr<ICameraDeviceService> device = nullptr;
    cameraService_->CreateCameraDevice(cameraIds[0], device);
    ASSERT_NE(device, nullptr);
    device->Open();

    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCaptureSession> camSession = nullptr;
    sptr<HStreamOperator> hStreamOperator = nullptr;
    SceneMode mode = PORTRAIT;
    InitSessionAndOperator(callerToken, mode, camSession, hStreamOperator);
    ASSERT_NE(camSession, nullptr);
    ASSERT_NE(hStreamOperator, nullptr);

    camSession->BeginConfig();
    camSession->Start();

    sptr<IConsumerSurface> Surface = IConsumerSurface::Create();
    sptr<IBufferProducer> producer = Surface->GetProducer();
    sptr<HStreamCapture> streamCapture = new (std::nothrow) HStreamCapture(producer, 4, 1280, 960);
    sptr<HStreamCapture> streamCapture1 = new (std::nothrow) HStreamCapture(producer, 3, 640, 480);
    sptr<HStreamRepeat> streamRepeat =
        new (std::nothrow) HStreamRepeat(producer, 4, 1280, 960, RepeatStreamType::PREVIEW);
    ASSERT_NE(streamRepeat, nullptr);

    EXPECT_EQ(camSession->AddOutput(StreamType::CAPTURE, streamCapture), 0);
    EXPECT_EQ(camSession->AddOutput(StreamType::CAPTURE, streamCapture1), 0);
    EXPECT_EQ(camSession->AddOutput(StreamType::REPEAT, streamRepeat), 0);

    CaptureErrorInfo it1;
    it1.streamId_ = 2;
    it1.error_ = BUFFER_LOST;
    CaptureErrorInfo it2;
    it2.streamId_ = 1;
    it2.error_ =  BUFFER_LOST;
    std::vector<CaptureErrorInfo> info = {};
    info.push_back(it1);
    info.push_back(it2);
    hStreamOperator->OnCaptureError(0, info);

    std::vector<int32_t> streamIds = {1, 2};
    hStreamOperator->OnFrameShutter(0, streamIds, 0);
    hStreamOperator->OnFrameShutterEnd(0, streamIds, 0);
    hStreamOperator->OnCaptureReady(0, streamIds, 0);

    device->Close();
    camSession->Release();
}

/*
 * Feature: coverage
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test HCaptureSession with anomalous branch.
 */
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_032, TestSize.Level1)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    sptr<ICameraDeviceService> device = nullptr;
    cameraService_->CreateCameraDevice(cameraIds[0], device);
    ASSERT_NE(device, nullptr);
    device->Open();

    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCaptureSession> camSession = nullptr;
    sptr<HStreamOperator> hStreamOperator = nullptr;
    SceneMode mode = PORTRAIT;
    InitSessionAndOperator(callerToken, mode, camSession, hStreamOperator);
    ASSERT_NE(camSession, nullptr);

    EXPECT_EQ(camSession->Start(), CAMERA_INVALID_STATE);

    sptr<IConsumerSurface> Surface = IConsumerSurface::Create();
    sptr<IBufferProducer> producer = Surface->GetProducer();
    sptr<HStreamRepeat> streamRepeat = new (std::nothrow) HStreamRepeat(producer, 0, 0, 0, RepeatStreamType::PREVIEW);
    ASSERT_NE(streamRepeat, nullptr);
    sptr<HStreamMetadata> streamMetadata= new(std::nothrow) HStreamMetadata(producer, 0, {1});
    ASSERT_NE(streamMetadata, nullptr);
    EXPECT_EQ(camSession->AddOutput(StreamType::REPEAT, streamRepeat), CAMERA_INVALID_STATE);
    EXPECT_EQ(camSession->RemoveOutput(StreamType::REPEAT, streamRepeat), CAMERA_INVALID_STATE);

    camSession->BeginConfig();
    camSession->Start();
    camSession->AddOutput(StreamType::METADATA, streamMetadata);
    camSession->AddOutput(StreamType::METADATA, streamMetadata);
    camSession->RemoveOutput(StreamType::METADATA, streamMetadata);
    camSession->AddInput(device);

    camSession->AddInput(device);

    sptr<ICaptureSessionCallback> callback1 = nullptr;
    camSession->SetCallback(callback1);

    sptr<IPressureStatusCallback> pressureCallback = nullptr;
    camSession->SetPressureCallback(pressureCallback);

    CameraInfoDumper infoDumper(0);
    camSession->DumpSessionInfo(infoDumper);
    camSession->DumpSessions(infoDumper);

    device->Close();
    camSession->Release();
}

/*
 * Feature: coverage
 * Function: Test HCaptureSession when stream is nullptr
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test HCaptureSession when stream is nullptr
 */
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_033, TestSize.Level1)
{
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCaptureSession> camSession = nullptr;
    sptr<HStreamOperator> hStreamOperator = nullptr;
    SceneMode mode = PORTRAIT;
    InitSessionAndOperator(callerToken, mode, camSession, hStreamOperator);
    ASSERT_NE(camSession, nullptr);

    std::vector<StreamInfo_V1_1> streamInfos = {};
    EXPECT_EQ(camSession->GetCurrentStreamInfos(streamInfos), 0);
    EXPECT_EQ(camSession->AddOutput(StreamType::REPEAT, nullptr), CAMERA_INVALID_ARG);
    EXPECT_EQ(camSession->RemoveOutputStream(nullptr), CAMERA_INVALID_ARG);
    camSession->Release();
}

/*
 * Feature: coverage
 * Function: Test HCaptureSession when cameraDevice_ is nullptr
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test HCaptureSession when cameraDevice_ is nullptr
 */
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_034, TestSize.Level1)
{
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCaptureSession> camSession = nullptr;
    sptr<HStreamOperator> hStreamOperator = nullptr;
    SceneMode mode = PORTRAIT;
    InitSessionAndOperator(callerToken, mode, camSession, hStreamOperator);
    ASSERT_NE(camSession, nullptr);

    camSession->cameraDevice_ = nullptr;
    EXPECT_EQ(camSession->LinkInputAndOutputs(), CAMERA_INVALID_SESSION_CFG);
    camSession->Release();
}

/*
 * Feature: coverage
 * Function: Test HCaptureSession with SetColorSpace
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test HCaptureSession with SetColorSpace
 */
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_035, TestSize.Level1)
{
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCaptureSession> camSession = nullptr;
    sptr<HStreamOperator> hStreamOperator = nullptr;
    SceneMode mode = PORTRAIT;
    InitSessionAndOperator(callerToken, mode, camSession, hStreamOperator);
    ASSERT_NE(camSession, nullptr);

    bool isNeedUpdate = false;
    int32_t colorSpace = static_cast<int32_t>(ColorSpace::SRGB);
    EXPECT_EQ(camSession->SetColorSpace(colorSpace, isNeedUpdate), CAMERA_INVALID_STATE);
    EXPECT_EQ(camSession->SetColorSpace(colorSpace, isNeedUpdate), CAMERA_INVALID_STATE);
    camSession->Release();
}

/*
 * Feature: coverage
 * Function: Test HCaptureSession with CheckIfColorSpaceMatchesFormat
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test HCaptureSession with CheckIfColorSpaceMatchesFormat
 */
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_036, TestSize.Level1)
{
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCaptureSession> camSession = nullptr;
    sptr<HStreamOperator> hStreamOperator = nullptr;
    SceneMode mode = PORTRAIT;
    InitSessionAndOperator(callerToken, mode, camSession, hStreamOperator);
    ASSERT_NE(camSession, nullptr);
    ASSERT_NE(hStreamOperator, nullptr);

    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    shared_ptr<OHOS::Camera::CameraMetadata> settings;
    cameraHostManager_->GetCameraAbility(cameraIds[0], settings);
    hStreamOperator->RestartStreams(settings);

    ColorSpace colorSpace = ColorSpace::SRGB;
    EXPECT_EQ(hStreamOperator->CheckIfColorSpaceMatchesFormat(colorSpace), 0);
    colorSpace = ColorSpace::BT2020_HLG ;
    EXPECT_EQ(hStreamOperator->CheckIfColorSpaceMatchesFormat(colorSpace), 0);
    colorSpace = ColorSpace::BT2020_PQ ;
    EXPECT_EQ(hStreamOperator->CheckIfColorSpaceMatchesFormat(colorSpace), 0);
    colorSpace = ColorSpace::BT2020_HLG_LIMIT ;
    EXPECT_EQ(hStreamOperator->CheckIfColorSpaceMatchesFormat(colorSpace), 0);
    colorSpace = ColorSpace::BT2020_PQ_LIMIT;
    EXPECT_EQ(hStreamOperator->CheckIfColorSpaceMatchesFormat(colorSpace), 0);
    camSession->Release();
}

/*
 * Feature: coverage
 * Function: Test HCaptureSession
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test HCaptureSession
 */
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_037, TestSize.Level1)
{
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCaptureSession> camSession = nullptr;
    sptr<HStreamOperator> hStreamOperator = nullptr;
    SceneMode mode = PORTRAIT;
    InitSessionAndOperator(callerToken, mode, camSession, hStreamOperator);
    ASSERT_NE(camSession, nullptr);

    camSession->Release();
}

/*
 * Feature: coverage
 * Function: Test HCaptureSession when isSessionStarted_ is true
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test HCaptureSession when isSessionStarted_ is true
 */
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_038, TestSize.Level1)
{
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCaptureSession> camSession = nullptr;
    sptr<HStreamOperator> hStreamOperator = nullptr;
    SceneMode mode = PORTRAIT;
    InitSessionAndOperator(callerToken, mode, camSession, hStreamOperator);
    ASSERT_NE(camSession, nullptr);
    ASSERT_NE(hStreamOperator, nullptr);

    hStreamOperator->SetColorSpaceForStreams();

    std::vector<StreamInfo_V1_1> streamInfos = {};
    hStreamOperator->CancelStreamsAndGetStreamInfos(streamInfos);

    camSession->isSessionStarted_ = true;

    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    shared_ptr<OHOS::Camera::CameraMetadata> settings;
    cameraHostManager_->GetCameraAbility(cameraIds[0], settings);
    hStreamOperator->RestartStreams(settings);
    camSession->Release();
}

/*
 * Feature: coverage
 * Function: Test HCaptureSession when cameraDevice is nullptr
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test HCaptureSession when cameraDevice is nullptr
 */
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_039, TestSize.Level1)
{
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCaptureSession> camSession = nullptr;
    sptr<HStreamOperator> hStreamOperator = nullptr;
    SceneMode mode = PORTRAIT;
    InitSessionAndOperator(callerToken, mode, camSession, hStreamOperator);
    ASSERT_NE(camSession, nullptr);

    float currentFps = 0;
    float currentZoomRatio = 0;
    std::vector<float> crossZoomAndTime = {0, 0};
    int32_t operationMode = 0;
    EXPECT_EQ(camSession->QueryFpsAndZoomRatio(currentFps, currentZoomRatio, crossZoomAndTime, operationMode), false);
    int32_t smoothZoomType = 0;
    float targetZoomRatio = 0;
    float duration = 0;
    EXPECT_EQ(camSession->SetSmoothZoom(smoothZoomType, operationMode,
        targetZoomRatio, duration), 11);
    camSession->Release();
}

/*
 * Feature: Framework
 * Function: Test fuzz
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test opMode PORTRAIT fuzz test
 */
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_040, TestSize.Level1)
{
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    SceneMode opMode = PORTRAIT;
    sptr<HCaptureSession> session = nullptr;
    HCaptureSession::NewInstance(callerToken, opMode, session);
    ASSERT_NE(session, nullptr);
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test CreateBurstDisplayName
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CreateBurstDisplayName
 */
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_041, TestSize.Level1)
{
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    SceneMode opMode = CAPTURE;
    sptr<HCaptureSession> session = nullptr;
    HCaptureSession::NewInstance(callerToken, opMode, session);
    std::string displayName = session->CreateBurstDisplayName(1, 1);
    cout << "displayName: " << displayName <<endl;
    ASSERT_NE(displayName, "");
    ASSERT_THAT(displayName, testing::EndsWith("_COVER"));
    displayName = session->CreateBurstDisplayName(2, 2);
    cout << "displayName: " << displayName <<endl;
    ASSERT_THAT(displayName, Not(testing::EndsWith("_COVER")));
    displayName = session->CreateBurstDisplayName(-1, -1);
    cout << "displayName: " << displayName <<endl;
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test HCaptureSessionCallbackStub with OnRemoteRequest
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test OnRemoteRequest for switch of CAMERA_CAPTURE_SESSION_ON_ERROR
 */
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_042, TestSize.Level1)
{
    MockHCaptureSessionCallbackStub stub;
    MessageParcel data;
    data.WriteInterfaceToken(stub.GetDescriptor());
    data.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    uint32_t code = static_cast<uint32_t>(ICaptureSessionCallbackIpcCode::COMMAND_ON_ERROR);
    EXPECT_CALL(stub, OnError(_))
        .WillOnce(Return(0));
    int errCode = stub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(errCode, 0);
}


/*
 * Feature: Framework
 * Function: Test HCaptureSessionCallbackStub with OnRemoteRequest
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test OnRemoteRequest for switch of default case
 */
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_043, TestSize.Level1)
{
    MockHCaptureSessionCallbackStub stub;
    MessageParcel data;
    data.WriteInterfaceToken(stub.GetDescriptor());
    data.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    
    uint32_t code = CAMERA_CAPTURE_SESSION_ON_DEFAULT;
    int errCode = stub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(errCode, IPC_STUB_UNKNOW_TRANS_ERR);
}

/*
 * Feature: Framework
 * Function: Test QueryZoomPerformance
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test QueryZoomPerformance normal branch
 */
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_044, TestSize.Level1)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    sptr<ICameraDeviceService> device = nullptr;
    cameraService_->CreateCameraDevice(cameraIds[0], device);
    ASSERT_NE(device, nullptr);
    device->Open();

    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCaptureSession> camSession = nullptr;
    SceneMode mode = PORTRAIT;
    HCaptureSession::NewInstance(callerToken, mode, camSession);
    ASSERT_NE(camSession, nullptr);

    EXPECT_EQ(camSession->BeginConfig(), CAMERA_OK);
    EXPECT_EQ(camSession->AddInput(device), CAMERA_OK);

    std::vector<float> crossZoomAndTime = {0, 0};
    int32_t operationMode = 10;
    camera_metadata_item_t zoomItem;
    zoomItem.count = 1;
    std::vector<uint32_t> elements = {10, 2, 3, 4, 5, 6, 7};
    zoomItem.data.ui32 = new uint32_t[elements.size()];
    for (size_t i = 0; i < elements.size(); ++i) {
        zoomItem.data.ui32[i] = elements[i];
    }
    EXPECT_EQ(camSession->QueryZoomPerformance(crossZoomAndTime, operationMode, zoomItem), true);

    operationMode = 1;
    camera_metadata_item_t zoomItem1;
    zoomItem1.count = 1;
    std::vector<uint32_t> elements1 = {10, 2, 3, 4, 5, 6, 7};
    zoomItem1.data.ui32 = new uint32_t[elements1.size()];
    for (size_t i = 0; i < elements1.size(); ++i) {
        zoomItem1.data.ui32[i] = elements1[i];
    }
    EXPECT_EQ(camSession->QueryZoomPerformance(crossZoomAndTime, operationMode, zoomItem1), true);
    EXPECT_EQ(device->Close(), CAMERA_OK);
    EXPECT_EQ(camSession->Release(), CAMERA_OK);
    delete[] zoomItem.data.ui32;
    delete[] zoomItem1.data.ui32;
}

/*
 * Feature: Framework
 * Function: Test GetRangeId
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetRangeId normal branch
 */
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_045, TestSize.Level1)
{
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCaptureSession> camSession = nullptr;
    SceneMode mode = PORTRAIT;
    HCaptureSession::NewInstance(callerToken, mode, camSession);
    ASSERT_NE(camSession, nullptr);

    float zoomRatio = 0.5;
    std::vector<float> crossZoom = {1.0, 2.0, 3.0};
    int32_t actualId = camSession->GetRangeId(zoomRatio, crossZoom);
    EXPECT_EQ(actualId, 0);

    zoomRatio = 4.0;
    actualId = camSession->GetRangeId(zoomRatio, crossZoom);
    EXPECT_EQ(actualId, 3);

    zoomRatio = 2.0;
    actualId = camSession->GetRangeId(zoomRatio, crossZoom);
    EXPECT_EQ(actualId, 2);
    camSession->Release();
}

/*
 * Feature: Framework
 * Function: Test isEqual
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test isEqual normal branch
 */
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_046, TestSize.Level1)
{
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCaptureSession> camSession = nullptr;
    SceneMode mode = PORTRAIT;
    HCaptureSession::NewInstance(callerToken, mode, camSession);
    ASSERT_NE(camSession, nullptr);

    float zoomPointA = 1.0f;
    float zoomPointB = 1.0f;
    bool result = camSession->isEqual(zoomPointA, zoomPointB);
    EXPECT_TRUE(result);

    zoomPointB = 1.1f;
    result = camSession->isEqual(zoomPointA, zoomPointB);
    EXPECT_FALSE(result);

    zoomPointB = 1.000001f;
    result = camSession->isEqual(zoomPointA, zoomPointB);
    EXPECT_TRUE(result);
    camSession->Release();
}

/*
 * Feature: Framework
 * Function: Test GetCrossZoomAndTime
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetCrossZoomAndTime normal branch
 */
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_047, TestSize.Level1)
{
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCaptureSession> camSession = nullptr;
    SceneMode mode = PORTRAIT;
    HCaptureSession::NewInstance(callerToken, mode, camSession);
    ASSERT_NE(camSession, nullptr);

    std::vector<float> crossZoomAndTime = {1.0, 2.0, 3.0, 0.0, 5.0, 6.0};
    std::vector<float> crossZoom;
    std::vector<std::vector<float>> crossTime(2, std::vector<float>(2, 0.0));
    camSession->GetCrossZoomAndTime(crossZoomAndTime, crossZoom, crossTime);

    EXPECT_EQ(crossZoom.size(), 1);
    EXPECT_EQ(crossZoom[0], 1.0);
    EXPECT_EQ(crossTime[0][0], 2.0);
    EXPECT_EQ(crossTime[0][1], 3.0);
    EXPECT_EQ(crossTime[1][0], 5.0);
    EXPECT_EQ(crossTime[1][1], 6.0);
    camSession->Release();
}

/*
 * Feature: Framework
 * Function: Test GetCrossWaitTime
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetCrossWaitTime when currentRangeId is WIDE_CAMERA_ZOOM_RANGE
 */
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_048, TestSize.Level1)
{
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCaptureSession> camSession = nullptr;
    SceneMode mode = PORTRAIT;
    HCaptureSession::NewInstance(callerToken, mode, camSession);
    ASSERT_NE(camSession, nullptr);

    std::vector<std::vector<float>> crossTime = {
        {100.0, 199.0, 370.0},
        {200.0, 299.0, 470.0},
        {300.0, 399.0, 570.0},
        {400.0, 499.0, 670.0}
    };

    int32_t currentRangeId = WIDE_CAMERA_ZOOM_RANGE;
    int32_t targetRangeId = TELE_CAMERA_ZOOM_RANGE;
    float actualWaitTime = camSession->GetCrossWaitTime(crossTime, targetRangeId, currentRangeId);
    EXPECT_EQ(actualWaitTime, 400.0);

    targetRangeId = WIDE_CAMERA_ZOOM_RANGE;
    actualWaitTime = camSession->GetCrossWaitTime(crossTime, targetRangeId, currentRangeId);
    EXPECT_EQ(actualWaitTime, 100.0);
    camSession->Release();
}

/*
 * Feature: Framework
 * Function: Test GetCrossWaitTime
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetCrossWaitTime when currentRangeId is MAIN_CAMERA_ZOOM_RANGE
 */
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_049, TestSize.Level1)
{
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCaptureSession> camSession = nullptr;
    SceneMode mode = PORTRAIT;
    HCaptureSession::NewInstance(callerToken, mode, camSession);
    ASSERT_NE(camSession, nullptr);

    std::vector<std::vector<float>> crossTime = {
        {100.0, 199.0, 370.0},
        {200.0, 299.0, 470.0},
        {300.0, 399.0, 570.0},
        {400.0, 499.0, 670.0}
    };

    int32_t currentRangeId = MAIN_CAMERA_ZOOM_RANGE;
    int32_t targetRangeId = TELE_CAMERA_ZOOM_RANGE;
    float actualWaitTime = camSession->GetCrossWaitTime(crossTime, targetRangeId, currentRangeId);
    EXPECT_EQ(actualWaitTime, 200.0);

    targetRangeId = WIDE_CAMERA_ZOOM_RANGE;
    actualWaitTime = camSession->GetCrossWaitTime(crossTime, targetRangeId, currentRangeId);
    EXPECT_EQ(actualWaitTime, 199.0);

    targetRangeId = MAIN_CAMERA_ZOOM_RANGE;
    actualWaitTime = camSession->GetCrossWaitTime(crossTime, targetRangeId, currentRangeId);
    EXPECT_EQ(actualWaitTime, 0.0);
    camSession->Release();
}

/*
 * Feature: Framework
 * Function: Test GetCrossWaitTime
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetCrossWaitTime when currentRangeId is TWO_X_EXIT_TELE_ZOOM_RANGE
 */
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_050, TestSize.Level1)
{
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCaptureSession> camSession = nullptr;
    SceneMode mode = PORTRAIT;
    HCaptureSession::NewInstance(callerToken, mode, camSession);
    ASSERT_NE(camSession, nullptr);

    std::vector<std::vector<float>> crossTime = {
        {100.0, 199.0, 370.0},
        {200.0, 299.0, 470.0},
        {300.0, 399.0, 570.0},
        {400.0, 499.0, 670.0}
    };

    int32_t currentRangeId = TWO_X_EXIT_TELE_ZOOM_RANGE;
    int32_t targetRangeId = TELE_CAMERA_ZOOM_RANGE;
    float actualWaitTime = camSession->GetCrossWaitTime(crossTime, targetRangeId, currentRangeId);
    EXPECT_EQ(actualWaitTime, 300.0);

    targetRangeId = WIDE_CAMERA_ZOOM_RANGE;
    actualWaitTime = camSession->GetCrossWaitTime(crossTime, targetRangeId, currentRangeId);
    EXPECT_EQ(actualWaitTime, 199.0);

    targetRangeId = TWO_X_EXIT_TELE_ZOOM_RANGE;
    actualWaitTime = camSession->GetCrossWaitTime(crossTime, targetRangeId, currentRangeId);
    EXPECT_EQ(actualWaitTime, 0.0);
    camSession->Release();
}

/*
 * Feature: Framework
 * Function: Test GetCrossWaitTime
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetCrossWaitTime when currentRangeId is TELE_CAMERA_ZOOM_RANGE
 */
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_051, TestSize.Level1)
{
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCaptureSession> camSession = nullptr;
    SceneMode mode = PORTRAIT;
    HCaptureSession::NewInstance(callerToken, mode, camSession);
    ASSERT_NE(camSession, nullptr);

    std::vector<std::vector<float>> crossTime = {
        {100.0, 199.0, 370.0},
        {200.0, 299.0, 470.0},
        {300.0, 399.0, 570.0},
        {400.0, 499.0, 670.0}
    };

    int32_t currentRangeId = TELE_CAMERA_ZOOM_RANGE;
    int32_t targetRangeId = WIDE_CAMERA_ZOOM_RANGE;
    float actualWaitTime = camSession->GetCrossWaitTime(crossTime, targetRangeId, currentRangeId);
    EXPECT_EQ(actualWaitTime, 499.0);

    targetRangeId = TWO_X_EXIT_TELE_ZOOM_RANGE;
    actualWaitTime = camSession->GetCrossWaitTime(crossTime, targetRangeId, currentRangeId);
    EXPECT_EQ(actualWaitTime, 399.0);

    targetRangeId = TELE_CAMERA_ZOOM_RANGE;
    actualWaitTime = camSession->GetCrossWaitTime(crossTime, targetRangeId, currentRangeId);
    EXPECT_EQ(actualWaitTime, 299.0);
    camSession->Release();
}

/*
 * Feature: Framework
 * Function: Test SetSmoothZoom
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetSmoothZoom when cameraDevice is not nullptr
 */
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_052, TestSize.Level1)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    sptr<ICameraDeviceService> device = nullptr;
    cameraService_->CreateCameraDevice(cameraIds[0], device);
    ASSERT_NE(device, nullptr);
    device->Open();

    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCaptureSession> session = nullptr;
    SceneMode mode = PORTRAIT;
    HCaptureSession::NewInstance(callerToken, mode, session);
    ASSERT_NE(session, nullptr);

    EXPECT_EQ(session->BeginConfig(), CAMERA_OK);
    EXPECT_EQ(session->AddInput(device), CAMERA_OK);

    int32_t operationMode = 1;
    int32_t smoothZoomType = 0;
    float targetZoomRatio = 30.0f;
    float duration = 0;
    EXPECT_EQ(session->SetSmoothZoom(smoothZoomType, operationMode,
        targetZoomRatio, duration), CAMERA_OK);

    EXPECT_EQ(device->Close(), CAMERA_OK);
    EXPECT_EQ(session->Release(), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test HCaptureSessionCallbackStub with OnRemoteRequest
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test OnRemoteRequest for switch of CAMERA_CAPTURE_SESSION_ON_ERROR
 */
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_053, TestSize.Level0)
{
    MockHPressureStatusCallbackStub stub;
    MessageParcel data;
    data.WriteInterfaceToken(stub.GetDescriptor());
    data.WriteInt32(0);
    MessageParcel reply;
    MessageOption option;
    uint32_t code = static_cast<uint32_t>(IPressureStatusCallbackIpcCode::COMMAND_ON_PRESSURE_STATUS_CHANGED);
    EXPECT_CALL(stub, OnPressureStatusChanged(_))
        .WillOnce(Return(0));
    int errCode = stub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(errCode, 0);
}

/*
 * Feature: Framework
 * Function: Test AddInput
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test AddInput when cameraDevice is nullptr
 */
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_054, TestSize.Level1)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    sptr<ICameraDeviceService> device = nullptr;
    cameraService_->CreateCameraDevice(cameraIds[0], device);
    ASSERT_NE(device, nullptr);
    device->Open();

    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCaptureSession> session = nullptr;
    SceneMode mode = PORTRAIT;
    HCaptureSession::NewInstance(callerToken, mode, session);
    ASSERT_NE(session, nullptr);

    EXPECT_EQ(session->BeginConfig(), CAMERA_OK);
    EXPECT_EQ(session->AddInput(nullptr), CAMERA_INVALID_ARG);
    EXPECT_EQ(session->AddInput(device), CAMERA_OK);
    EXPECT_EQ(device->Close(), CAMERA_OK);
    EXPECT_EQ(session->Release(), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test AddOutput
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test AddOutput when stream is nullptr
 */
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_055, TestSize.Level1)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    sptr<ICameraDeviceService> device = nullptr;
    cameraService_->CreateCameraDevice(cameraIds[0], device);
    ASSERT_NE(device, nullptr);
    device->Open();

    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCaptureSession> session = nullptr;
    SceneMode mode = PORTRAIT;
    HCaptureSession::NewInstance(callerToken, mode, session);
    ASSERT_NE(session, nullptr);

    EXPECT_EQ(session->BeginConfig(), CAMERA_OK);
    EXPECT_EQ(session->AddInput(device), CAMERA_OK);
    EXPECT_EQ(session->AddOutput(StreamType::REPEAT, nullptr), CAMERA_INVALID_ARG);
    EXPECT_EQ(device->Close(), CAMERA_OK);
    EXPECT_EQ(session->Release(), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test RemoveInput
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test RemoveInput when cameraDevice is nullptr
 */
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_056, TestSize.Level1)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    sptr<ICameraDeviceService> device = nullptr;
    cameraService_->CreateCameraDevice(cameraIds[0], device);
    ASSERT_NE(device, nullptr);
    device->Open();

    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCaptureSession> session = nullptr;
    SceneMode mode = PORTRAIT;
    HCaptureSession::NewInstance(callerToken, mode, session);
    ASSERT_NE(session, nullptr);

    EXPECT_EQ(session->BeginConfig(), CAMERA_OK);
    EXPECT_EQ(session->AddInput(device), CAMERA_OK);
    EXPECT_EQ(session->RemoveInput(nullptr), CAMERA_INVALID_ARG);
    EXPECT_EQ(device->Close(), CAMERA_OK);
    EXPECT_EQ(session->Release(), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test RemoveOutput
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test RemoveOutput when stream is nullptr
 */
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_057, TestSize.Level1)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    sptr<ICameraDeviceService> device = nullptr;
    cameraService_->CreateCameraDevice(cameraIds[0], device);
    ASSERT_NE(device, nullptr);
    device->Open();

    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCaptureSession> session = nullptr;
    SceneMode mode = PORTRAIT;
    HCaptureSession::NewInstance(callerToken, mode, session);
    ASSERT_NE(session, nullptr);

    EXPECT_EQ(session->BeginConfig(), CAMERA_OK);
    EXPECT_EQ(session->AddInput(device), CAMERA_OK);

    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    sptr<IBufferProducer> producer = surface->GetProducer();
    sptr<HStreamRepeat> streamRepeat = new (std::nothrow) HStreamRepeat(producer, DEFAULT_FORMAT,
        DEFAULT_WIDTH, DEFAULT_HEIGHT, RepeatStreamType::PREVIEW);
    ASSERT_NE(streamRepeat, nullptr);

    EXPECT_EQ(session->AddOutput(StreamType::REPEAT, streamRepeat), CAMERA_OK);
    EXPECT_EQ(session->RemoveOutput(StreamType::REPEAT, nullptr), CAMERA_INVALID_ARG);
    EXPECT_EQ(session->RemoveOutput(StreamType::REPEAT, streamRepeat), CAMERA_OK);
    EXPECT_EQ(device->Close(), CAMERA_OK);
    EXPECT_EQ(session->Release(), CAMERA_OK);
}

/*
 * Feature: coverage
 * Function: Test CommitConfigWithValidation when cameraDevice_ is nullptr
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CommitConfigWithValidation when cameraDevice_ is nullptr
 */
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_058, TestSize.Level1)
{
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCaptureSession> session = nullptr;
    SceneMode mode = PORTRAIT;
    HCaptureSession::NewInstance(callerToken, mode, session);
    ASSERT_NE(session, nullptr);

    session->cameraDevice_ = nullptr;
    EXPECT_EQ(session->CommitConfigWithValidation(), CAMERA_INVALID_STATE);
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test SetColorSpace
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * Function: Test SetColorSpace noamal branch when isNeedUpdate is true
 */
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_059, TestSize.Level0)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    sptr<ICameraDeviceService> device = nullptr;
    cameraService_->CreateCameraDevice(cameraIds[0], device);
    ASSERT_NE(device, nullptr);
    device->Open();

    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCaptureSession> session = nullptr;
    int32_t opMode = SceneMode::NORMAL;
    HCaptureSession::NewInstance(callerToken, opMode, session);
    ASSERT_NE(session, nullptr);

    EXPECT_EQ(session->BeginConfig(), CAMERA_OK);
    EXPECT_EQ(session->AddInput(device), CAMERA_OK);

    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    sptr<IBufferProducer> producer = surface->GetProducer();
    sptr<HStreamRepeat> streamRepeat = new (std::nothrow) HStreamRepeat(producer, DEFAULT_FORMAT,
        DEFAULT_WIDTH, DEFAULT_HEIGHT, RepeatStreamType::PREVIEW);
    ASSERT_NE(streamRepeat, nullptr);
    EXPECT_EQ(session->AddOutput(StreamType::REPEAT, streamRepeat), CAMERA_OK);
    session->CommitConfig();

    EXPECT_NE(session->SetColorSpace(ColorSpace::P3_HLG, true), CAMERA_INVALID_STATE);

    EXPECT_EQ(device->Close(), CAMERA_OK);
    EXPECT_EQ(session->Release(), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test DynamicConfigStream
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test DynamicConfigStream when currentState is SESSION_STARTED
 */
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_060, TestSize.Level1)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    sptr<ICameraDeviceService> device = nullptr;
    cameraService_->CreateCameraDevice(cameraIds[0], device);
    ASSERT_NE(device, nullptr);
    device->Open();

    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCaptureSession> session = nullptr;
    SceneMode mode = PORTRAIT;
    HCaptureSession::NewInstance(callerToken, mode, session);
    ASSERT_NE(session, nullptr);

    session->stateMachine_.currentState_ = CaptureSessionState::SESSION_STARTED;
    session->DynamicConfigStream();

    EXPECT_EQ(device->Close(), CAMERA_OK);
    EXPECT_EQ(session->Release(), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test RemoveInput
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test RemoveInput normal branch
 */
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_061, TestSize.Level1)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    sptr<ICameraDeviceService> device = nullptr;
    cameraService_->CreateCameraDevice(cameraIds[0], device);
    ASSERT_NE(device, nullptr);
    device->Open();

    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCaptureSession> session = nullptr;
    SceneMode mode = PORTRAIT;
    HCaptureSession::NewInstance(callerToken, mode, session);
    ASSERT_NE(session, nullptr);

    EXPECT_EQ(session->BeginConfig(), CAMERA_OK);
    EXPECT_EQ(session->AddInput(device), CAMERA_OK);
    EXPECT_EQ(session->RemoveInput(device), CAMERA_OK);
    EXPECT_EQ(device->Close(), CAMERA_OK);
    EXPECT_EQ(session->Release(), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test CommitConfigWithValidation
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CommitConfigWithValidation not allowed
 */
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_062, TestSize.Level1)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    sptr<ICameraDeviceService> device = nullptr;
    cameraService_->CreateCameraDevice(cameraIds[0], device);
    ASSERT_NE(device, nullptr);
    device->Open();

    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCaptureSession> session = nullptr;
    SceneMode mode = SECURE;
    HCaptureSession::NewInstance(callerToken, mode, session);
    ASSERT_NE(session, nullptr);

    EXPECT_EQ(session->BeginConfig(), CAMERA_OK);
    EXPECT_EQ(session->AddInput(device), CAMERA_OK);
    EXPECT_EQ(session->CommitConfigWithValidation(), CAMERA_OPERATION_NOT_ALLOWED);
    EXPECT_EQ(session->RemoveInput(device), CAMERA_OK);
    EXPECT_EQ(device->Close(), CAMERA_OK);
    EXPECT_EQ(session->Release(), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test CommitConfig
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CommitConfig when currentState is not SESSION_CONFIG_COMMITTED
 */
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_063, TestSize.Level1)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    sptr<ICameraDeviceService> device = nullptr;
    cameraService_->CreateCameraDevice(cameraIds[0], device);
    ASSERT_NE(device, nullptr);
    device->Open();

    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCaptureSession> session = nullptr;
    SceneMode mode = PORTRAIT;
    HCaptureSession::NewInstance(callerToken, mode, session);
    ASSERT_NE(session, nullptr);

    EXPECT_EQ(session->CommitConfig(), CAMERA_INVALID_STATE);
    EXPECT_EQ(device->Close(), CAMERA_OK);
    EXPECT_EQ(session->Release(), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test CommitConfig
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CommitConfig when need commit
 */
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_064, TestSize.Level1)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    sptr<ICameraDeviceService> device = nullptr;
    cameraService_->CreateCameraDevice(cameraIds[0], device);
    ASSERT_NE(device, nullptr);
    device->Open();

    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCaptureSession> session = nullptr;
    SceneMode mode = PORTRAIT;
    HCaptureSession::NewInstance(callerToken, mode, session);
    ASSERT_NE(session, nullptr);

    EXPECT_EQ(session->SetCommitConfigFlag(true), CAMERA_OK);
    session->stateMachine_.currentState_ = CaptureSessionState::SESSION_CONFIG_INPROGRESS;
    EXPECT_EQ(session->CommitConfig(), CAMERA_OK);
    EXPECT_EQ(device->Close(), CAMERA_OK);
    EXPECT_EQ(session->Release(), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test GetCrossWaitTime
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetCrossWaitTime when currentRangeId is not range
 */
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_065, TestSize.Level1)
{
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCaptureSession> camSession = nullptr;
    SceneMode mode = PORTRAIT;
    HCaptureSession::NewInstance(callerToken, mode, camSession);
    ASSERT_NE(camSession, nullptr);

    std::vector<std::vector<float>> crossTime = {
        {100.0, 199.0, 370.0},
        {200.0, 299.0, 470.0},
        {300.0, 399.0, 570.0},
        {400.0, 499.0, 670.0}
    };

    int32_t currentRangeId = 10;
    int32_t targetRangeId = 10;
    float actualWaitTime = camSession->GetCrossWaitTime(crossTime, targetRangeId, currentRangeId);
    EXPECT_EQ(actualWaitTime, 0.0);

    camSession->Release();
}

/*
 * Feature: Framework
 * Function: Test EnableMovingPhoto
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test EnableMovingPhoto when device is nullptr
 */
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_066, TestSize.Level1)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    sptr<ICameraDeviceService> device = nullptr;
    cameraService_->CreateCameraDevice(cameraIds[0], device);
    ASSERT_NE(device, nullptr);
    device->Open();

    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCaptureSession> session = nullptr;
    SceneMode mode = SECURE;
    HCaptureSession::NewInstance(callerToken, mode, session);
    ASSERT_NE(session, nullptr);

    EXPECT_EQ(session->GetCameraDevice(), nullptr);
    EXPECT_EQ(session->EnableMovingPhoto(true), CAMERA_OK);
    EXPECT_EQ(device->Close(), CAMERA_OK);
    EXPECT_EQ(session->Release(), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test GetConcurrentCameraIds
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetConcurrentCameraIds when isSessionStarted_ is false
 */
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_067, TestSize.Level1)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    sptr<ICameraDeviceService> device = nullptr;
    cameraService_->CreateCameraDevice(cameraIds[0], device);
    ASSERT_NE(device, nullptr);
    device->Open();

    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCaptureSession> session = nullptr;
    SceneMode mode = SECURE;
    HCaptureSession::NewInstance(callerToken, mode, session);
    ASSERT_NE(session, nullptr);

    EXPECT_EQ(session->isSessionStarted_, false);
    pid_t pid = session->GetPid();
    EXPECT_EQ(session->GetConcurrentCameraIds(pid), "Concurrency cameras:[]");
    EXPECT_EQ(device->Close(), CAMERA_OK);
    EXPECT_EQ(session->Release(), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test GetConcurrentCameraIds
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetConcurrentCameraIds when device is nullptr
 */
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_068, TestSize.Level1)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    sptr<ICameraDeviceService> device = nullptr;
    cameraService_->CreateCameraDevice(cameraIds[0], device);
    ASSERT_NE(device, nullptr);
    device->Open();

    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCaptureSession> session = nullptr;
    SceneMode mode = SECURE;
    HCaptureSession::NewInstance(callerToken, mode, session);
    ASSERT_NE(session, nullptr);

    session->isSessionStarted_ = true;
    EXPECT_EQ(session->GetCameraDevice(), nullptr);
    pid_t pid = session->GetPid();
    EXPECT_EQ(session->GetConcurrentCameraIds(pid), "Concurrency cameras:[]");
    EXPECT_EQ(device->Close(), CAMERA_OK);
    EXPECT_EQ(session->Release(), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test GetConcurrentCameraIds
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetConcurrentCameraIds normal branch
 */
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_069, TestSize.Level1)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    sptr<ICameraDeviceService> device = nullptr;
    cameraService_->CreateCameraDevice(cameraIds[0], device);
    ASSERT_NE(device, nullptr);
    device->Open();

    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCaptureSession> session = nullptr;
    SceneMode mode = SECURE;
    HCaptureSession::NewInstance(callerToken, mode, session);
    ASSERT_NE(session, nullptr);

    session->isSessionStarted_ = true;
    EXPECT_EQ(session->BeginConfig(), CAMERA_OK);
    EXPECT_EQ(session->AddInput(device), CAMERA_OK);
    pid_t pid = session->GetPid();
    EXPECT_NE(session->GetConcurrentCameraIds(pid), "Concurrency cameras:[]");
    EXPECT_EQ(session->RemoveInput(device), CAMERA_OK);
    EXPECT_EQ(device->Close(), CAMERA_OK);
    EXPECT_EQ(session->Release(), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test Stop
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test Stop when currentState is not SESSION_CONFIG_COMMITTED
 */
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_070, TestSize.Level1)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    sptr<ICameraDeviceService> device = nullptr;
    cameraService_->CreateCameraDevice(cameraIds[0], device);
    ASSERT_NE(device, nullptr);
    device->Open();

    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCaptureSession> session = nullptr;
    SceneMode mode = PORTRAIT;
    HCaptureSession::NewInstance(callerToken, mode, session);
    ASSERT_NE(session, nullptr);

    EXPECT_EQ(session->Stop(), CAMERA_INVALID_STATE);
    EXPECT_EQ(device->Close(), CAMERA_OK);
    EXPECT_EQ(session->Release(), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test OperatePermissionCheck
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * Function: Test OperatePermissionCheck normal branch
 */
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_071, TestSize.Level1)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    sptr<ICameraDeviceService> device = nullptr;
    cameraService_->CreateCameraDevice(cameraIds[0], device);
    ASSERT_NE(device, nullptr);
    device->Open();

    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCaptureSession> session = nullptr;
    SceneMode mode = PORTRAIT;
    HCaptureSession::NewInstance(callerToken, mode, session);
    ASSERT_NE(session, nullptr);

    EXPECT_EQ(session->OperatePermissionCheck(INTERFACE_CODE), CAMERA_OK);
    EXPECT_EQ(device->Close(), CAMERA_OK);
    EXPECT_EQ(session->Release(), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test OperatePermissionCheck
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * Function: Test OperatePermissionCheck when interfaceCode is default 0
 */
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_072, TestSize.Level1)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    sptr<ICameraDeviceService> device = nullptr;
    cameraService_->CreateCameraDevice(cameraIds[0], device);
    ASSERT_NE(device, nullptr);
    device->Open();

    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCaptureSession> session = nullptr;
    SceneMode mode = PORTRAIT;
    HCaptureSession::NewInstance(callerToken, mode, session);
    ASSERT_NE(session, nullptr);

    uint32_t interfaceCode = 0;
    EXPECT_EQ(session->OperatePermissionCheck(interfaceCode), CAMERA_OK);
    EXPECT_EQ(device->Close(), CAMERA_OK);
    EXPECT_EQ(session->Release(), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test CreateDisplayName
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * Function: Test CreateDisplayName normal branch
 */
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_073, TestSize.Level1)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    sptr<ICameraDeviceService> device = nullptr;
    cameraService_->CreateCameraDevice(cameraIds[0], device);
    ASSERT_NE(device, nullptr);
    device->Open();

    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCaptureSession> session = nullptr;
    SceneMode mode = PORTRAIT;
    HCaptureSession::NewInstance(callerToken, mode, session);
    ASSERT_NE(session, nullptr);

    std::string suffix = "132";
    EXPECT_NE(session->CreateDisplayName(suffix), "");
    EXPECT_EQ(device->Close(), CAMERA_OK);
    EXPECT_EQ(session->Release(), CAMERA_OK);
}

/*
 * Feature: HCaptureSession
 * Function: Test session Start
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test session Start normal branch when cameraDevice is nullptr
 */
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_074, TestSize.Level1)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    sptr<ICameraDeviceService> device = nullptr;
    cameraService_->CreateCameraDevice(cameraIds[0], device);
    ASSERT_NE(device, nullptr);
    device->Open();

    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCaptureSession> session = nullptr;
    SceneMode mode = PORTRAIT;
    HCaptureSession::NewInstance(callerToken, mode, session);
    ASSERT_NE(session, nullptr);

    EXPECT_EQ(session->BeginConfig(), CAMERA_OK);
    EXPECT_EQ(session->SetCommitConfigFlag(true), CAMERA_OK);
    EXPECT_EQ(session->CommitConfig(), CAMERA_OK);
    session->Start();

    EXPECT_EQ(session->Stop(), CAMERA_OK);
    EXPECT_EQ(device->Close(), CAMERA_OK);
    EXPECT_EQ(session->Release(), CAMERA_OK);
}

/*
 * Feature: HCaptureSession
 * Function: Test session Start
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test session Start normal branch when cameraDevice is not nullptr
 */
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_075, TestSize.Level1)
{
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    sptr<ICameraDeviceService> device = nullptr;
    cameraService_->CreateCameraDevice(cameraIds[0], device);
    ASSERT_NE(device, nullptr);
    device->Open();

    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCaptureSession> session = nullptr;
    SceneMode mode = PORTRAIT;
    HCaptureSession::NewInstance(callerToken, mode, session);
    ASSERT_NE(session, nullptr);

    EXPECT_EQ(session->BeginConfig(), CAMERA_OK);
    EXPECT_EQ(session->AddInput(device), CAMERA_OK);
    EXPECT_EQ(session->SetCommitConfigFlag(true), CAMERA_OK);
    EXPECT_EQ(session->CommitConfig(), CAMERA_OK);
    session->Start();
    EXPECT_EQ(session->Stop(), CAMERA_OK);

    EXPECT_EQ(session->BeginConfig(), CAMERA_OK);
    EXPECT_EQ(session->RemoveInput(device), CAMERA_OK);
    EXPECT_EQ(session->CommitConfig(), CAMERA_OK);
    EXPECT_EQ(device->Close(), CAMERA_OK);
    EXPECT_EQ(session->Release(), CAMERA_OK);
}

} // namespace CameraStandard
} // namespace OHOS
