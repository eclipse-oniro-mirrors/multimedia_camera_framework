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
#include "gmock/gmock.h"
#include "hap_token_info.h"
#include "ipc_skeleton.h"
#include "metadata_utils.h"
#include "nativetoken_kit.h"
#include "surface.h"
#include "test_common.h"
#include "token_setproc.h"
#include "os_account_manager.h"
#include "picture.h"
#include "hcapture_session_callback_stub.h"
#include "camera_service_ipc_interface_code.h"

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

class MockHCaptureSessionCallbackStub : public HCaptureSessionCallbackStub {
public:
    MOCK_METHOD1(OnError, int32_t(int32_t errorCode));
    ~MockHCaptureSessionCallbackStub() {}
};
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

    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    sptr<ICameraDeviceService> device = nullptr;
    cameraService_->CreateCameraDevice(cameraIds[0], device);
    ASSERT_NE(device, nullptr);
    device->Open();

    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCaptureSession> session = new (std::nothrow) HCaptureSession(callerToken, SceneMode::NORMAL);
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

    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    sptr<ICameraDeviceService> device = nullptr;
    cameraService_->CreateCameraDevice(cameraIds[0], device);
    ASSERT_NE(device, nullptr);
    device->Open();

    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCaptureSession> session = new (std::nothrow) HCaptureSession(callerToken, SceneMode::NORMAL);
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

    MEDIA_INFO_LOG("hcapture_session_unit_test_002 end");
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
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_003, TestSize.Level0)
{
    MEDIA_INFO_LOG("hcapture_session_unit_test_003 start");

    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    sptr<ICameraDeviceService> device = nullptr;
    cameraService_->CreateCameraDevice(cameraIds[0], device);
    ASSERT_NE(device, nullptr);
    device->Open();

    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCaptureSession> session = new (std::nothrow) HCaptureSession(callerToken, SceneMode::NORMAL);
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
    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    sptr<ICameraDeviceService> device = nullptr;
    cameraService_->CreateCameraDevice(cameraIds[0], device);
    ASSERT_NE(device, nullptr);
    device->Open();

    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCaptureSession> session = new (std::nothrow) HCaptureSession(callerToken, SceneMode::NORMAL);
    ASSERT_NE(session, nullptr);

    EXPECT_EQ(session->BeginConfig(), CAMERA_OK);
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

    EXPECT_EQ(device->Close(), CAMERA_OK);
    EXPECT_EQ(session->Release(), CAMERA_OK);

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
            MEDIA_INFO_LOG("Not support tag OHOS_ABILITY_CAMERA_MODES, test case end");
            return;
        }
        ASSERT_EQ(retCode, CAM_META_SUCCESS);
        ASSERT_NE(item.count, 0);

        for (uint32_t i = 0; i < item.count; i++) {
            supportedModes.emplace_back(static_cast<OperationMode>(item.data.u8[i]));
        }
        ASSERT_NE(supportedModes.size(), 0);
        if (find(supportedModes.begin(), supportedModes.end(), OperationMode::SECURE) != supportedModes.end()) {
            uint64_t secureSeqId = 1;
            device->OpenSecureCamera(&secureSeqId);

            uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
            sptr<HCaptureSession> session = new (std::nothrow) HCaptureSession(callerToken, SceneMode::NORMAL);
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

    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    sptr<ICameraDeviceService> device = nullptr;
    cameraService_->CreateCameraDevice(cameraIds[0], device);
    ASSERT_NE(device, nullptr);
    device->Open();

    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCaptureSession> session = new (std::nothrow) HCaptureSession(callerToken, SceneMode::NORMAL);
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

    EXPECT_EQ(session->SetColorSpace(ColorSpace::BT2020_HLG,
        ColorSpace::BT2020_HLG, true), CAMERA_OPERATION_NOT_ALLOWED);

    EXPECT_EQ(device->Close(), CAMERA_OK);
    EXPECT_EQ(session->Release(), CAMERA_OK);

    MEDIA_INFO_LOG("hcapture_session_unit_test_006 end");
}

/*
 * Feature: HCaptureSession
 * Function: Test cancel stream and get stream infos with capture session configure preview stream,
 * metadata stream and capture stream in the context of session start and session stop
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test cancel stream and get stream infos with capture session configure preview stream,
 * metadata stream and capture stream in the context of session start and session stop
 */
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_007, TestSize.Level0)
{
    MEDIA_INFO_LOG("hcapture_session_unit_test_007 start");

    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    sptr<ICameraDeviceService> device = nullptr;
    cameraService_->CreateCameraDevice(cameraIds[0], device);
    ASSERT_NE(device, nullptr);
    device->Open();

    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCaptureSession> session = new (std::nothrow) HCaptureSession(callerToken, SceneMode::NORMAL);
    ASSERT_NE(session, nullptr);

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
    session->CancelStreamsAndGetStreamInfos(streamInfos);
    ASSERT_TRUE(streamInfos.size() != 0);

    session->Stop();
    session->CancelStreamsAndGetStreamInfos(streamInfos);
    ASSERT_TRUE(streamInfos.size() != 0);

    EXPECT_EQ(device->Close(), CAMERA_OK);
    EXPECT_EQ(session->Release(), CAMERA_OK);

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

    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    sptr<ICameraDeviceService> device = nullptr;
    cameraService_->CreateCameraDevice(cameraIds[0], device);
    ASSERT_NE(device, nullptr);
    device->Open();

    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCaptureSession> session = new (std::nothrow) HCaptureSession(callerToken, SceneMode::NORMAL);
    ASSERT_NE(session, nullptr);

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
    session->StartMovingPhoto(streamRepeat2);

    EXPECT_EQ(session->EnableMovingPhoto(false), CAMERA_OK);
    session->Start();

    session->Stop();
    EXPECT_EQ(device->Close(), CAMERA_OK);
    EXPECT_EQ(session->Release(), CAMERA_OK);

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

    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    sptr<ICameraDeviceService> device = nullptr;
    cameraService_->CreateCameraDevice(cameraIds[0], device);
    ASSERT_NE(device, nullptr);
    device->Open();

    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCaptureSession> session = new (std::nothrow) HCaptureSession(callerToken, SceneMode::NORMAL);
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

    MEDIA_INFO_LOG("hcapture_session_unit_test_011 end");
}

/*
 * Feature: HCaptureSession
 * Function: Test get output status with capture session configure null capture stream,
 * normal preview stream and video stream
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test get output status with capture session configure null capture stream,
 * normal preview stream and video stream
 */
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_012, TestSize.Level0)
{
    MEDIA_INFO_LOG("hcapture_session_unit_test_012 start");

    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    sptr<ICameraDeviceService> device = nullptr;
    cameraService_->CreateCameraDevice(cameraIds[0], device);
    ASSERT_NE(device, nullptr);
    device->Open();

    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCaptureSession> session = new (std::nothrow) HCaptureSession(callerToken, SceneMode::NORMAL);
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
    session->CreateMediaLibrary(photoProxy, uri, cameraShotType, burstKey, timestamp);

    EXPECT_EQ(session->Release(), CAMERA_OK);

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
    session->CreateMediaLibrary(Media::Picture::Create(surfaceBuffer), photoProxy, uri, cameraShotType,
        burstKey, timestamp);

    EXPECT_EQ(session->Release(), CAMERA_OK);

    MEDIA_INFO_LOG("hcapture_session_unit_test_014 end");
}

/*
 * Feature: HCaptureSession
 * Function: Test onCaptureStarted and OnCaptureStarted_V1_2 when GetHdiStreamByStreamID is null,
 * return camera invalid arg
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test onCaptureStarted and OnCaptureStarted_V1_2 when GetHdiStreamByStreamID is null,
 * return camera invalid arg
 */
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_015, TestSize.Level0)
{
    MEDIA_INFO_LOG("hcapture_session_unit_test_015 start");

    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    sptr<ICameraDeviceService> device = nullptr;
    cameraService_->CreateCameraDevice(cameraIds[0], device);
    ASSERT_NE(device, nullptr);
    device->Open();

    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCaptureSession> session = new (std::nothrow) HCaptureSession(callerToken, SceneMode::NORMAL);
    ASSERT_NE(session, nullptr);

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
    EXPECT_EQ(session->OnCaptureStarted(captureId, streamIds), CAMERA_INVALID_ARG);

    HDI::Camera::V1_2::CaptureStartedInfo it1;
    it1.streamId_ = 1;
    it1.exposureTime_ = 1;
    HDI::Camera::V1_2::CaptureStartedInfo it2;
    it2.streamId_ = 2;
    it2.exposureTime_ = 2;
    std::vector<OHOS::HDI::Camera::V1_2::CaptureStartedInfo> captureStartedInfo = {};
    captureStartedInfo.push_back(it1);
    captureStartedInfo.push_back(it2);
    EXPECT_EQ(session->OnCaptureStarted_V1_2(captureId, captureStartedInfo), CAMERA_INVALID_ARG);

    EXPECT_EQ(device->Close(), CAMERA_OK);
    EXPECT_EQ(session->Release(), CAMERA_OK);

    MEDIA_INFO_LOG("hcapture_session_unit_test_015 end");
}

/*
 * Feature: HCaptureSession
 * Function: Test OnCaptureEnded and OnCaptureEndedExt when GetHdiStreamByStreamID is null,
 * return camera invalid arg
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test OnCaptureEnded and OnCaptureEndedExt when GetHdiStreamByStreamID is null,
 * return camera invalid arg
 */
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_016, TestSize.Level0)
{
    MEDIA_INFO_LOG("hcapture_session_unit_test_016 start");

    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    sptr<ICameraDeviceService> device = nullptr;
    cameraService_->CreateCameraDevice(cameraIds[0], device);
    ASSERT_NE(device, nullptr);
    device->Open();

    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCaptureSession> session = new (std::nothrow) HCaptureSession(callerToken, SceneMode::NORMAL);
    ASSERT_NE(session, nullptr);

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
    EXPECT_EQ(session->OnCaptureEndedExt(captureId, infos), CAMERA_INVALID_ARG);

    EXPECT_EQ(device->Close(), CAMERA_OK);
    EXPECT_EQ(session->Release(), CAMERA_OK);

    MEDIA_INFO_LOG("hcapture_session_unit_test_016 end");
}

/*
 * Feature: HCaptureSession
 * Function: Test OnCaptureError when stream type is repeat or capture
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test OnCaptureError when stream type is repeat or capture
 */
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_017, TestSize.Level0)
{
    MEDIA_INFO_LOG("hcapture_session_unit_test_017 start");

    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    sptr<ICameraDeviceService> device = nullptr;
    cameraService_->CreateCameraDevice(cameraIds[0], device);
    ASSERT_NE(device, nullptr);
    device->Open();

    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCaptureSession> session = new (std::nothrow) HCaptureSession(callerToken, SceneMode::NORMAL);
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
    session->OnCaptureError(captureId, captureErrorInfo);

    EXPECT_EQ(device->Close(), CAMERA_OK);
    EXPECT_EQ(session->Release(), CAMERA_OK);

    MEDIA_INFO_LOG("hcapture_session_unit_test_017 end");
}

/*
 * Feature: HCaptureSession
 * Function: Test OnResult when stream type is not metadata, session return camera invalid arg
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test OnResult when stream type is not metadata, session return camera invalid arg
 */
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_018, TestSize.Level0)
{
    MEDIA_INFO_LOG("hcapture_session_unit_test_018 start");

    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    sptr<ICameraDeviceService> device = nullptr;
    cameraService_->CreateCameraDevice(cameraIds[0], device);
    ASSERT_NE(device, nullptr);
    device->Open();

    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCaptureSession> session = new (std::nothrow) HCaptureSession(callerToken, SceneMode::NORMAL);
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

    int32_t streamId = 1;
    std::vector<uint8_t> result = {0, 1};
    EXPECT_EQ(session->OnResult(streamId, result), CAMERA_INVALID_ARG);
    streamId = 2;
    EXPECT_EQ(session->OnResult(streamId, result), CAMERA_INVALID_ARG);

    EXPECT_EQ(device->Close(), CAMERA_OK);
    EXPECT_EQ(session->Release(), CAMERA_OK);

    MEDIA_INFO_LOG("hcapture_session_unit_test_018 end");
}

/*
 * Feature: HCaptureSession
 * Function: Test AddStream when stream exists already, add same stream fail
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test AddStream when stream exists already, add same stream fail
 */
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_019, TestSize.Level0)
{
    MEDIA_INFO_LOG("hcapture_session_unit_test_019 start");

    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    sptr<ICameraDeviceService> device = nullptr;
    cameraService_->CreateCameraDevice(cameraIds[0], device);
    ASSERT_NE(device, nullptr);
    device->Open();

    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCaptureSession> session = new (std::nothrow) HCaptureSession(callerToken, SceneMode::NORMAL);
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

    MEDIA_INFO_LOG("hcapture_session_unit_test_019 end");
}

/*
 * Feature: HCaptureSession
 * Function: Test add input output, when session state is not in-progress, return camera invalid state
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test add input output, when session state is not in-progress, return camera invalid state
 */
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_020, TestSize.Level0)
{
    MEDIA_INFO_LOG("hcapture_session_unit_test_020 start");

    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    sptr<ICameraDeviceService> device = nullptr;
    cameraService_->CreateCameraDevice(cameraIds[0], device);
    ASSERT_NE(device, nullptr);
    device->Open();

    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCaptureSession> session = new (std::nothrow) HCaptureSession(callerToken, SceneMode::NORMAL);
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

    MEDIA_INFO_LOG("hcapture_session_unit_test_020 end");
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
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_021, TestSize.Level0)
{
    MEDIA_INFO_LOG("hcapture_session_unit_test_021 start");

    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    sptr<ICameraDeviceService> device = nullptr;
    cameraService_->CreateCameraDevice(cameraIds[0], device);
    ASSERT_NE(device, nullptr);
    device->Open();

    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCaptureSession> session = new (std::nothrow) HCaptureSession(callerToken, SceneMode::NORMAL);
    ASSERT_NE(session, nullptr);

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

    EXPECT_EQ(session->AddOutputStream(nullptr), CAMERA_INVALID_ARG);
    EXPECT_EQ(session->AddOutputStream(streamMetadata), CAMERA_OK);
    EXPECT_EQ(session->AddOutputStream(streamMetadata), CAMERA_INVALID_SESSION_CFG);
    EXPECT_EQ(streamRepeat->Release(), CAMERA_OK);
    EXPECT_EQ(session->AddOutputStream(streamRepeat), CAMERA_INVALID_ARG);

    EXPECT_EQ(device->Close(), CAMERA_OK);
    EXPECT_EQ(session->Release(), CAMERA_OK);

    MEDIA_INFO_LOG("hcapture_session_unit_test_021 end");
}

/*
 * Feature: HCaptureSession
 * Function: Test UpdateStreamInfos when camera device in null, return camera unknown error
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test UpdateStreamInfos when camera device in null, return camera unknown error
 */
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_022, TestSize.Level0)
{
    MEDIA_INFO_LOG("hcapture_session_unit_test_022 start");

    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCaptureSession> session = new (std::nothrow) HCaptureSession(callerToken, SceneMode::NORMAL);
    ASSERT_NE(session, nullptr);

    EXPECT_EQ(session->UpdateStreamInfos(), CAMERA_UNKNOWN_ERROR);
    EXPECT_EQ(session->Release(), CAMERA_OK);

    MEDIA_INFO_LOG("hcapture_session_unit_test_022 end");
}

/*
 * Feature: HCaptureSession
 * Function: Test session stop, when other stream undefined exists, other types of streams cannot be stopped
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test session stop, when other undefined stream exists, other types of streams cannot be stopped
 */
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_023, TestSize.Level0)
{
    MEDIA_INFO_LOG("hcapture_session_unit_test_023 start");

    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    sptr<ICameraDeviceService> device = nullptr;
    cameraService_->CreateCameraDevice(cameraIds[0], device);
    ASSERT_NE(device, nullptr);
    device->Open();

    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCaptureSession> session = new (std::nothrow) HCaptureSession(callerToken, SceneMode::NORMAL);
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

    session->AddOutputStream(streamRepeat);
    session->CommitConfig();
    session->Start();

    EXPECT_EQ(session->Stop(), CAMERA_OK);
    EXPECT_EQ(device->Close(), CAMERA_OK);
    EXPECT_EQ(session->Release(), CAMERA_OK);

    MEDIA_INFO_LOG("hcapture_session_unit_test_023 end");
}

/*
 * Feature: HCaptureSession
 * Function: Test get session state, when another capture session state exists,
 * other state cannot be found in SESSION_STATE_STRING_MAP
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * Function: Test get session state, when another capture session state exists,
 * other state cannot be found in SESSION_STATE_STRING_MAP
 */
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_024, TestSize.Level0)
{
    MEDIA_INFO_LOG("hcapture_session_unit_test_024 start");

    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCaptureSession> session = new (std::nothrow) HCaptureSession(callerToken, SceneMode::NORMAL);
    ASSERT_NE(session, nullptr);

    uint32_t otherCaptureSessionState = 6;
    session->stateMachine_.currentState_ = static_cast<CaptureSessionState>(otherCaptureSessionState);
    EXPECT_EQ(session->GetSessionState(), std::to_string(otherCaptureSessionState));

    session->stateMachine_.currentState_ = CaptureSessionState::SESSION_INIT;
    EXPECT_EQ(session->GetSessionState(), "Init");
    EXPECT_EQ(session->Release(), CAMERA_OK);

    MEDIA_INFO_LOG("hcapture_session_unit_test_024 end");
}

/*
 * Feature: HCaptureSession
 * Function: Test EnableMovingPhotoMirror with preview stream and livephoto stream, interface call is normal
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test EnableMovingPhotoMirror with preview stream and livephoto stream, interface call is normal
 */
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_025, TestSize.Level0)
{
    MEDIA_INFO_LOG("hcapture_session_unit_test_025 start");

    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    sptr<ICameraDeviceService> device = nullptr;
    cameraService_->CreateCameraDevice(cameraIds[0], device);
    ASSERT_NE(device, nullptr);
    device->Open();

    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCaptureSession> session = new (std::nothrow) HCaptureSession(callerToken, SceneMode::NORMAL);
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

    MEDIA_INFO_LOG("hcapture_session_unit_test_025 end");
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
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_026, TestSize.Level0)
{
    MEDIA_INFO_LOG("hcapture_session_unit_test_026 start");

    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    sptr<ICameraDeviceService> device = nullptr;
    cameraService_->CreateCameraDevice(cameraIds[0], device);
    ASSERT_NE(device, nullptr);
    device->Open();

    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCaptureSession> session = new (std::nothrow) HCaptureSession(callerToken, SceneMode::NORMAL);
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

    MEDIA_INFO_LOG("hcapture_session_unit_test_026 end");
}

/*
 * Feature: HCaptureSession
 * Function: Test ExpandMovingPhotoRepeatStream with CreateMovingPhotoSurfaceWrapper
 * or CreateMovingPhotoStreamRepeat fail
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * Function: Test ExpandMovingPhotoRepeatStream, CreateMovingPhotoSurfaceWrapper when width or height is invalid,
 * and livePhotoStreamRepeat_ needs to be released and recreated when it is not null
 */
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_027, TestSize.Level0)
{
    MEDIA_INFO_LOG("hcapture_session_unit_test_027 start");

    std::vector<string> cameraIds;
    cameraService_->GetCameraIds(cameraIds);
    ASSERT_NE(cameraIds.size(), 0);
    cameraService_->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    sptr<ICameraDeviceService> device = nullptr;
    cameraService_->CreateCameraDevice(cameraIds[0], device);
    ASSERT_NE(device, nullptr);
    device->Open();

    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCaptureSession> session = new (std::nothrow) HCaptureSession(callerToken, SceneMode::NORMAL);
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

    MEDIA_INFO_LOG("hcapture_session_unit_test_027 end");
}

/*
 * Feature: Framework
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test HCaptureSession with anomalous branch
 */
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_028, TestSize.Level0)
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
    SceneMode mode = PORTRAIT;
    sptr<HCaptureSession> camSession = new (std::nothrow) HCaptureSession(callerToken, mode);
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

    sptr<IStreamCommon> stream_2 = nullptr;
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
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_029, TestSize.Level0)
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
    SceneMode mode = PORTRAIT;
    sptr<HCaptureSession> camSession = new (std::nothrow) HCaptureSession(callerToken, mode);
    ASSERT_NE(camSession, nullptr);

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
    camSession->OnCaptureError(0, info);

    std::vector<int32_t> streamIds = {1, 2};
    camSession->OnFrameShutter(0, streamIds, 0);
    camSession->OnFrameShutterEnd(0, streamIds, 0);
    camSession->OnCaptureReady(0, streamIds, 0);
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
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_030, TestSize.Level0)
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
    SceneMode mode = PORTRAIT;
    sptr<HCaptureSession> camSession = new (std::nothrow) HCaptureSession(callerToken, mode);
    ASSERT_NE(camSession, nullptr);

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
    camSession->OnCaptureError(0, info);

    std::vector<int32_t> streamIds = {1, 2};
    camSession->OnFrameShutter(0, streamIds, 0);
    camSession->OnFrameShutterEnd(0, streamIds, 0);
    camSession->OnCaptureReady(0, streamIds, 0);

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
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_031, TestSize.Level0)
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
    sptr<HCaptureSession> camSession = new (std::nothrow) HCaptureSession(callerToken, PORTRAIT);
    ASSERT_NE(camSession, nullptr);
    EXPECT_EQ(camSession->CommitConfig(), CAMERA_INVALID_STATE);
    camSession->BeginConfig();
    camSession->Start();

    sptr<IConsumerSurface> Surface = IConsumerSurface::Create();
    sptr<IBufferProducer> producer = Surface->GetProducer();
    sptr<HStreamCapture> streamCapture= new(std::nothrow) HStreamCapture(producer, 0, 0, 0);
    ASSERT_NE(streamCapture, nullptr);

    EXPECT_EQ(camSession->AddOutput(StreamType::CAPTURE, streamCapture), 0);

    camSession->CommitConfig();

    CaptureErrorInfo it1;
    it1.streamId_ = 0;
    it1.error_ = BUFFER_LOST;
    CaptureErrorInfo it2;
    it2.streamId_ = 1;
    it2.error_ =  BUFFER_LOST;
    std::vector<CaptureErrorInfo> info = {};
    info.push_back(it1);
    info.push_back(it2);
    camSession->OnCaptureError(0, info);

    std::vector<int32_t> streamIds = {0, 1, 2};
    camSession->OnFrameShutter(0, streamIds, 0);
    camSession->OnFrameShutterEnd(0, streamIds, 0);
    camSession->OnCaptureReady(0, streamIds, 0);
    camSession->BeginConfig();

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
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_032, TestSize.Level0)
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
    SceneMode mode = PORTRAIT;
    sptr<HCaptureSession> camSession = new (std::nothrow) HCaptureSession(callerToken, mode);
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
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_033, TestSize.Level0)
{
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    SceneMode mode = PORTRAIT;
    sptr<HCaptureSession> camSession = new (std::nothrow) HCaptureSession(callerToken, mode);
    ASSERT_NE(camSession, nullptr);

    std::vector<StreamInfo_V1_1> streamInfos = {};
    EXPECT_EQ(camSession->GetCurrentStreamInfos(streamInfos), 0);
    EXPECT_EQ(camSession->AddOutputStream(nullptr), CAMERA_INVALID_ARG);
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
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_034, TestSize.Level0)
{
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    SceneMode mode = PORTRAIT;
    sptr<HCaptureSession> camSession = new (std::nothrow) HCaptureSession(callerToken, mode);
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
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_035, TestSize.Level0)
{
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    SceneMode mode = PORTRAIT;
    sptr<HCaptureSession> camSession = new (std::nothrow) HCaptureSession(callerToken, mode);
    ASSERT_NE(camSession, nullptr);

    bool isNeedUpdate = false;
    ColorSpace colorSpace = ColorSpace::SRGB;
    ColorSpace captureColorSpace = ColorSpace::SRGB;
    camSession->currColorSpace_ = ColorSpace::BT709;
    camSession->currCaptureColorSpace_ = ColorSpace::BT709;
    EXPECT_EQ(camSession->SetColorSpace(colorSpace, captureColorSpace, isNeedUpdate), CAMERA_INVALID_STATE);
    camSession->currColorSpace_ = ColorSpace::SRGB;
    EXPECT_EQ(camSession->SetColorSpace(colorSpace, captureColorSpace, isNeedUpdate), CAMERA_INVALID_STATE);
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
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_036, TestSize.Level0)
{
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    SceneMode mode = PORTRAIT;
    sptr<HCaptureSession> camSession = new (std::nothrow) HCaptureSession(callerToken, mode);
    ASSERT_NE(camSession, nullptr);

    camSession->RestartStreams();

    ColorSpace colorSpace = ColorSpace::SRGB;
    EXPECT_EQ(camSession->CheckIfColorSpaceMatchesFormat(colorSpace), 0);
    colorSpace = ColorSpace::BT2020_HLG ;
    EXPECT_EQ(camSession->CheckIfColorSpaceMatchesFormat(colorSpace), 0);
    colorSpace = ColorSpace::BT2020_PQ ;
    EXPECT_EQ(camSession->CheckIfColorSpaceMatchesFormat(colorSpace), 0);
    colorSpace = ColorSpace::BT2020_HLG_LIMIT ;
    EXPECT_EQ(camSession->CheckIfColorSpaceMatchesFormat(colorSpace), 0);
    colorSpace = ColorSpace::BT2020_PQ_LIMIT;
    EXPECT_EQ(camSession->CheckIfColorSpaceMatchesFormat(colorSpace), 0);
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
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_037, TestSize.Level0)
{
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    SceneMode mode = PORTRAIT;
    sptr<HCaptureSession> camSession = new (std::nothrow) HCaptureSession(callerToken, mode);
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
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_038, TestSize.Level0)
{
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    SceneMode mode = PORTRAIT;
    sptr<HCaptureSession> camSession = new (std::nothrow) HCaptureSession(callerToken, mode);
    ASSERT_NE(camSession, nullptr);

    camSession->SetColorSpaceForStreams();

    std::vector<StreamInfo_V1_1> streamInfos = {};
    camSession->CancelStreamsAndGetStreamInfos(streamInfos);

    camSession->isSessionStarted_ = true;
    camSession->RestartStreams();
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
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_039, TestSize.Level0)
{
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    SceneMode mode = PORTRAIT;
    sptr<HCaptureSession> camSession = new (std::nothrow) HCaptureSession(callerToken, mode);
    ASSERT_NE(camSession, nullptr);

    float currentFps = 0;
    float currentZoomRatio = 0;
    EXPECT_EQ(camSession->QueryFpsAndZoomRatio(currentFps, currentZoomRatio), false);
    std::vector<float> crossZoomAndTime = {0, 0};
    int32_t operationMode = 0;
    EXPECT_EQ(camSession->QueryZoomPerformance(crossZoomAndTime, operationMode), false);
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
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_040, TestSize.Level0)
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
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_041, TestSize.Level0)
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
HWTEST_F(HCaptureSessionUnitTest, hcapture_session_unit_test_042, TestSize.Level0)
{
    MockHCaptureSessionCallbackStub stub;
    MessageParcel data;
    data.WriteInterfaceToken(stub.GetDescriptor());
    data.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    uint32_t code = CaptureSessionCallbackInterfaceCode::CAMERA_CAPTURE_SESSION_ON_ERROR;
    EXPECT_CALL(stub, OnError(_))
        .WillOnce(Return(0));
    int errCode = stub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(errCode, 0);
}
} // namespace CameraStandard
} // namespace OHOS
