/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#include "camera_deferred_post_processor_unittest.h"

#include <fcntl.h>

#include "gmock/gmock.h"
#include "events_info.h"
#include "photo_post_processor.h"
#include "basic_definitions.h"
#include "accesstoken_kit.h"
#include "ipc_skeleton.h"
#include "nativetoken_kit.h"
#include "os_account_manager.h"
#include "photo_process_command.h"
#include "service_died_command.h"
#include "token_setproc.h"
#include "v1_5/ivideo_process_session.h"
#include "video_process_command.h"
#include "video_post_processor.h"
#include "dp_utils.h"
#include "dps.h"
#include "v1_5/iimage_process_service.h"
#include "v1_5/ivideo_process_service.h"
#include "picture_interface.h"
#include "media_manager_proxy.h"
#include "test_token.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS::CameraStandard::DeferredProcessing;

namespace OHOS {
namespace CameraStandard {
namespace {
    const std::string MEDIA_ROOT = "/data/test/media/";
    const std::string VIDEO_PATH = MEDIA_ROOT + "test_video.mp4";
    const std::string VIDEO_TEMP_PATH = MEDIA_ROOT + "test_video_temp.mp4";
    const std::string VIDEO_ID = "20240101240000000";
    constexpr int32_t OK = 0;
    constexpr int32_t ERROR = -1;
    constexpr int32_t VIDEO_WIDTH = 1920;
    constexpr int32_t VIDEO_HIGHT = 1080;
}

void DeferredPostPorcessorUnitTest::SetUpTestCase(void)
{
    ASSERT_TRUE(TestToken().GetAllCameraPermission());
}

void DeferredPostPorcessorUnitTest::TearDownTestCase(void) {}

void DeferredPostPorcessorUnitTest::SetUp()
{
    srcFd_ = open(VIDEO_PATH.c_str(), O_RDONLY);
    dtsFd_ = open(VIDEO_TEMP_PATH.c_str(), O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
}

void DeferredPostPorcessorUnitTest::TearDown()
{
    if (srcFd_ > 0) {
        close(srcFd_);
    }
    if (dtsFd_ > 0) {
        close(dtsFd_);
    }
}

class VideoPostProcessor::VideoProcessListener : public HDI::Camera::V1_4::IVideoProcessCallback {
public:
    explicit VideoProcessListener(const std::weak_ptr<VideoProcessResult>& processResult)
        : processResult_(processResult)
    {
        DP_DEBUG_LOG("entered.");
    }

    int32_t OnProcessDone(const std::string& videoId) override;
    int32_t OnProcessDone(const std::string& videoId,
        const sptr<HDI::Camera::V1_0::MapDataSequenceable>& metaData) override;
    int32_t OnError(const std::string& videoId, HDI::Camera::V1_2::ErrorCode errorCode) override;
    int32_t OnStatusChanged(HDI::Camera::V1_2::SessionStatus status) override;

private:
    std::weak_ptr<VideoProcessResult> processResult_;
};

class MockVideoProcessSession : public HDI::Camera::V1_5::IVideoProcessSession {
public:
    MOCK_METHOD(int32_t, GetPendingVideos, (std::vector<std::string>& videoIds), (override));
    MOCK_METHOD(int32_t, Prepare, (const std::string& videoId, int fd,
        std::vector<OHOS::HDI::Camera::V1_3::StreamDescription>& streamDescs), (override));
    MOCK_METHOD(int32_t, Prepare, (const std::string& videoId, const std::vector<int>& fds,
        std::vector<OHOS::HDI::Camera::V1_3::StreamDescription>& streamDescs), (override));
    MOCK_METHOD(int32_t, CreateStreams, (const std::vector<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>& streamInfos),
        (override));
    MOCK_METHOD(int32_t, CommitStreams, (const std::vector<uint8_t>& modeSetting), (override));
    MOCK_METHOD(int32_t, ReleaseStreams, (const std::vector<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>& streamInfos),
        (override));
    MOCK_METHOD(int32_t, ProcessVideo, (const std::string& videoId, uint64_t timestamp), (override));
    MOCK_METHOD(int32_t, RemoveVideo, (const std::string& videoId), (override));
    MOCK_METHOD(int32_t, Interrupt, (), (override));
    MOCK_METHOD(int32_t, Reset, (), (override));

    MockVideoProcessSession()
    {
        ON_CALL(*this, GetPendingVideos).WillByDefault(Return(OK));
        ON_CALL(*this, Prepare(_,Matcher<int>(_),_)).WillByDefault(Return(OK));
        ON_CALL(*this, Prepare(_,Matcher<const std::vector<int>&>(_),_)).WillByDefault(Return(OK));
        ON_CALL(*this, CreateStreams).WillByDefault(Return(OK));
        ON_CALL(*this, CommitStreams).WillByDefault(Return(OK));
        ON_CALL(*this, ReleaseStreams).WillByDefault(Return(OK));
        ON_CALL(*this, ProcessVideo).WillByDefault(Return(OK));
        ON_CALL(*this, RemoveVideo).WillByDefault(Return(OK));
        ON_CALL(*this, Interrupt).WillByDefault(Return(OK));
        ON_CALL(*this, Reset).WillByDefault(Return(OK));
    }
};

/*
 * Feature: Framework
 * Function: Test the exception branch of the Photo Post Processor when the session is nulptr
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the exception branch of the Photo Post Processor when the session is nulptr
 */
HWTEST_F(DeferredPostPorcessorUnitTest, deferred_post_processor_unittest_001, TestSize.Level0)
{
    auto postProcessor = CreateShared<PhotoPostProcessor>(userId_);
    ASSERT_NE(postProcessor, nullptr);
    postProcessor->Initialize();
    postProcessor->session_ = nullptr;
    std::string imageId = "testImageId";
    postProcessor->RemoveImage(imageId);
    postProcessor->Reset();
    postProcessor->SetExecutionMode(ExecutionMode::HIGH_PERFORMANCE);
    postProcessor->DisconnectService();
    int32_t ret = postProcessor->GetConcurrency(ExecutionMode::HIGH_PERFORMANCE);
    EXPECT_EQ(ret, 1);
}

HWTEST_F(DeferredPostPorcessorUnitTest, deferred_post_processor_unittest_002, TestSize.Level0) {
    CameraStandard::DeferredProcessing::ImageInfo imageInfo;
    CallbackType expectedType = static_cast<CallbackType>(1);
    imageInfo.SetType(expectedType);
    EXPECT_EQ(imageInfo.type_, expectedType);
    expectedType = static_cast<CallbackType>(2);
    imageInfo.SetType(expectedType);
    EXPECT_EQ(imageInfo.type_, expectedType);
    expectedType = static_cast<CallbackType>(3);
    imageInfo.SetType(expectedType);
    EXPECT_EQ(imageInfo.type_, expectedType);
}

HWTEST_F(DeferredPostPorcessorUnitTest, deferred_post_processor_unittest_003, TestSize.Level0) {
    CameraStandard::DeferredProcessing::ImageInfo imageInfo;
    imageInfo.picture_ = nullptr;
    std::shared_ptr<PictureIntf> actualPicture = imageInfo.GetPicture();
    EXPECT_EQ(actualPicture, nullptr);
}

HWTEST_F(DeferredPostPorcessorUnitTest, deferred_post_processor_unittest_004, TestSize.Level0) {
    auto sharedBuffer = std::make_unique<SharedBuffer>(1024);
    CameraStandard::DeferredProcessing::ImageInfo imageInfo;
    imageInfo.SetBuffer(std::move(sharedBuffer));
    EXPECT_NE(imageInfo.sharedBuffer_, nullptr);
    EXPECT_EQ(imageInfo.type_, CallbackType::IMAGE_PROCESS_DONE);
}

HWTEST_F(DeferredPostPorcessorUnitTest, deferred_post_processor_unittest_005, TestSize.Level0) {
    int32_t dataSize = 1024;
    bool isHighQuality = true;
    uint32_t cloudFlag = 0x1234;
    uint32_t captureFlag = 123;
    DpsMetadata metaData;
    metaData.Set("cloudFlag", cloudFlag);
    metaData.Set("captureFlag", captureFlag);
    CameraStandard::DeferredProcessing::ImageInfo imageInfo(dataSize, isHighQuality, cloudFlag, captureFlag, metaData);
    EXPECT_EQ(imageInfo.dataSize_, dataSize);
    EXPECT_EQ(imageInfo.isHighQuality_, isHighQuality);
    EXPECT_EQ(imageInfo.cloudFlag_, cloudFlag);
}

/*
 * Feature: Framework
 * Function: Test Executing with abnormal branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test Executing with abnormal branch
 */
HWTEST_F(DeferredPostPorcessorUnitTest, deferred_post_processor_unittest_006, TestSize.Level0)
{
    std::string imageId = "testImageId";
    auto successCommand = CreateShared<PhotoProcessSuccessCommand>(userId_, imageId, nullptr);
    EXPECT_EQ(successCommand->Executing(), DP_NULL_POINTER);
    DpsError errorCode = DpsError::DPS_ERROR_IMAGE_PROC_TIMEOUT;
    auto failedCommand = CreateShared<PhotoProcessFailedCommand>(userId_, imageId, errorCode);
    EXPECT_EQ(failedCommand->Executing(), DP_NULL_POINTER);
    auto photoDiedCommand = CreateShared<PhotoDiedCommand>(userId_);
    EXPECT_EQ(photoDiedCommand->Executing(), DP_NULL_POINTER);
    auto videoDiedCommand = CreateShared<VideoDiedCommand>(userId_);
    EXPECT_EQ(videoDiedCommand->Executing(), DP_NULL_POINTER);
    auto videoProcessSuccessCommand = CreateShared<VideoProcessSuccessCommand>(userId_, imageId);
    EXPECT_EQ(videoProcessSuccessCommand->Executing(), DP_NULL_POINTER);
    auto videoProcessFailedCommand = CreateShared<VideoProcessFailedCommand>(userId_, imageId, errorCode);
    EXPECT_EQ(videoProcessFailedCommand->Executing(), DP_NULL_POINTER);
}

/*
 * Feature: Framework
 * Function: Test OnError with abnormal branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test OnError with abnormal branch
 */
HWTEST_F(DeferredPostPorcessorUnitTest, deferred_post_processor_unittest_007, TestSize.Level0)
{
    auto postProcessor = VideoPostProcessor::Create(userId_);
    ASSERT_NE(postProcessor, nullptr);
    postProcessor->SetExecutionMode(LOAD_BALANCE);
    postProcessor->SetDefaultExecutionMode();
    std::vector<std::string> testStrings = {"test1", "test2"};
    uint8_t randomNum = 1;
    std::string videoId(testStrings[randomNum % testStrings.size()]);
    auto isAutoSuspend = true;
    DpsFdPtr inputFd = std::make_shared<DpsFd>(dup(srcFd_));
    DpsFdPtr outFd = std::make_shared<DpsFd>(dup(dtsFd_));
    DeferredVideoJobPtr jobPtr = std::make_shared<DeferredVideoJob>(videoId, inputFd, outFd, nullptr, nullptr);
    jobPtr->SetExecutionMode(LOAD_BALANCE);
    jobPtr->SetChargState(isAutoSuspend);
    EXPECT_NE(jobPtr, nullptr);
}

HWTEST_F(DeferredPostPorcessorUnitTest, deferred_post_processor_unittest_008, TestSize.Level1)
{
    int32_t userId = 1;
    auto sharedResult = std::make_shared<VideoProcessResult>(userId);
    std::string videoId = "testId";
    auto metaData = sptr<HDI::Camera::V1_0::MapDataSequenceable>::MakeSptr();
    metaData->Set(VideoMetadataKeys::SCALING_FACTOR, 1.0);
    metaData->Set(VideoMetadataKeys::INTERPOLATION_FRAME_PTS, "0");
    metaData->Set(VideoMetadataKeys::STAGE_VID, "0");
    auto ret = sharedResult->ProcessVideoInfo(videoId, metaData);
    EXPECT_EQ(ret, DP_OK);
}

/*
 * Feature: Framework
 * Function: Test GetPendingVideos with normal branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetPendingVideos with normal branch
 */
HWTEST_F(DeferredPostPorcessorUnitTest, deferred_post_processor_unittest_009, TestSize.Level0)
{
    auto postProcessor = VideoPostProcessor::Create(userId_);
    auto session = sptr<MockVideoProcessSession>::MakeSptr();
    postProcessor->sessionV1_3_ = session;
    std::vector<std::string> resultVideos {"video1", "video2", "video3"};
    EXPECT_CALL(*session, GetPendingVideos(_)).WillOnce([&](std::vector<std::string>& pendingVideos) {
        pendingVideos = resultVideos;
        return OK;
    });
    std::vector<std::string> pendingVideos;
    auto ret = postProcessor->GetPendingVideos(pendingVideos);
    EXPECT_EQ(ret, true);
    EXPECT_EQ(pendingVideos.size(), resultVideos.size());
    postProcessor->sessionV1_3_ = nullptr;
}

/*
 * Feature: Framework
 * Function: Test GetPendingVideos with abnormal branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetPendingVideos with abnormal branch
 */
HWTEST_F(DeferredPostPorcessorUnitTest, deferred_post_processor_unittest_010, TestSize.Level0)
{
    auto postProcessor = VideoPostProcessor::Create(userId_);
    auto session = sptr<MockVideoProcessSession>::MakeSptr();
    postProcessor->sessionV1_3_ = session;
    EXPECT_CALL(*session, GetPendingVideos(_)).WillOnce(Return(ERROR));
    std::vector<std::string> pendingVideos;
    auto ret = postProcessor->GetPendingVideos(pendingVideos);
    EXPECT_EQ(ret, false);
    postProcessor->sessionV1_3_ = nullptr;
}

/*
 * Feature: Framework
 * Function: Test GetPendingVideos with abnormal branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetPendingVideos with abnormal branch
 */
HWTEST_F(DeferredPostPorcessorUnitTest, deferred_post_processor_unittest_011, TestSize.Level0)
{
    auto postProcessor = VideoPostProcessor::Create(userId_);
    std::vector<std::string> pendingVideos;
    auto ret = postProcessor->GetPendingVideos(pendingVideos);
    EXPECT_EQ(ret, false);
}

/*
 * Feature: Framework
 * Function: Test PrepareStreams with normal branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test PrepareStreams with normal branch
 */
HWTEST_F(DeferredPostPorcessorUnitTest, deferred_post_processor_unittest_012, TestSize.Level0)
{
    auto postProcessor = VideoPostProcessor::Create(userId_);
    auto session = sptr<MockVideoProcessSession>::MakeSptr();
    postProcessor->sessionV1_3_ = session;
    DpsFdPtr inputFd = std::make_shared<DpsFd>(dup(srcFd_));
    DpsFdPtr outFd = std::make_shared<DpsFd>(dup(dtsFd_));
    DeferredVideoJobPtr jobPtr = std::make_shared<DeferredVideoJob>(VIDEO_ID, inputFd, outFd, nullptr, nullptr);
    std::vector<StreamDescription> resultDescs {
        StreamDescription {
            .streamId = 0,
            .type = HDI::Camera::V1_3::MediaStreamType::MEDIA_STREAM_TYPE_VIDEO,
        },
        StreamDescription {
            .streamId = 1,
            .type = HDI::Camera::V1_3::MediaStreamType::MEDIA_STREAM_TYPE_MAKER,
        },
    };
    EXPECT_CALL(*session, Prepare(_, Matcher<int>(_), _))
        .WillOnce([&](const std::string& videoId, int fd,
                      std::vector<OHOS::HDI::Camera::V1_3::StreamDescription>& streamDescs) {
            streamDescs = resultDescs;
            return OK;
        });
    auto result = postProcessor->PrepareStreams(jobPtr);
    EXPECT_EQ(result.size(), resultDescs.size());
    postProcessor->sessionV1_3_ = nullptr;
}

/*
 * Feature: Framework
 * Function: Test PrepareStreams with abnormal branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test PrepareStreams with abnormal branch
 */
HWTEST_F(DeferredPostPorcessorUnitTest, deferred_post_processor_unittest_013, TestSize.Level0)
{
    auto postProcessor = VideoPostProcessor::Create(userId_);
    auto session = sptr<MockVideoProcessSession>::MakeSptr();
    postProcessor->sessionV1_3_ = session;
    DpsFdPtr inputFd = std::make_shared<DpsFd>(dup(srcFd_));
    DpsFdPtr outFd = std::make_shared<DpsFd>(dup(dtsFd_));
    DeferredVideoJobPtr jobPtr = std::make_shared<DeferredVideoJob>(VIDEO_ID, inputFd, outFd, nullptr, nullptr);
    std::vector<StreamDescription> resultDescs;
    EXPECT_CALL(*session, Prepare(_, Matcher<int>(_), _))
        .WillOnce([&](const std::string& videoId, int fd,
                      std::vector<OHOS::HDI::Camera::V1_3::StreamDescription>& streamDescs) {
            streamDescs = resultDescs;
            return ERROR;
        });
    auto result = postProcessor->PrepareStreams(jobPtr);
    EXPECT_EQ(result.size(), 0);
    postProcessor->sessionV1_3_ = nullptr;
}

/*
 * Feature: Framework
 * Function: Test RemoveRequest with normal branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test RemoveRequest with normal branch
 */
HWTEST_F(DeferredPostPorcessorUnitTest, deferred_post_processor_unittest_014, TestSize.Level0)
{
    auto postProcessor = VideoPostProcessor::Create(userId_);
    postProcessor->runningId_.emplace(VIDEO_ID);
    auto session = sptr<MockVideoProcessSession>::MakeSptr();
    postProcessor->sessionV1_3_ = session;
    EXPECT_CALL(*session, RemoveVideo).WillOnce(Return(OK));
    postProcessor->RemoveRequest(VIDEO_ID);
    EXPECT_EQ(postProcessor->runningId_.empty(), true);
    postProcessor->sessionV1_3_ = nullptr;
}

/*
 * Feature: Framework
 * Function: Test RemoveRequest with abnormal branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test RemoveRequest with abnormal branch
 */
HWTEST_F(DeferredPostPorcessorUnitTest, deferred_post_processor_unittest_015, TestSize.Level0)
{
    auto postProcessor = VideoPostProcessor::Create(userId_);
    postProcessor->runningId_.emplace(VIDEO_ID);
    postProcessor->RemoveRequest(VIDEO_ID);
    EXPECT_EQ(postProcessor->runningId_.empty(), true);
}

/*
 * Feature: Framework
 * Function: Test PauseRequest with normal branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test PauseRequest with normal branch
 */
HWTEST_F(DeferredPostPorcessorUnitTest, deferred_post_processor_unittest_016, TestSize.Level0)
{
    auto postProcessor = VideoPostProcessor::Create(userId_);
    auto session = sptr<MockVideoProcessSession>::MakeSptr();
    postProcessor->sessionV1_3_ = session;
    postProcessor->PauseRequest(VIDEO_ID, SchedulerType::VIDEO_CAMERA_STATE);
    EXPECT_EQ(postProcessor->runningId_.empty(), true);
    postProcessor->sessionV1_3_ = nullptr;
}

/*
 * Feature: Framework
 * Function: Test PauseRequest with abnormal branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test PauseRequest with abnormal branch
 */
HWTEST_F(DeferredPostPorcessorUnitTest, deferred_post_processor_unittest_017, TestSize.Level0)
{
    auto postProcessor = VideoPostProcessor::Create(userId_);
    postProcessor->PauseRequest(VIDEO_ID, SchedulerType::VIDEO_CAMERA_STATE);
    EXPECT_EQ(postProcessor->runningId_.empty(), true);
}

/*
 * Feature: Framework
 * Function: Test OnStateChanged with normal branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test OnStateChanged with normal branch
 */
HWTEST_F(DeferredPostPorcessorUnitTest, deferred_post_processor_unittest_018, TestSize.Level0)
{
    auto postProcessor = VideoPostProcessor::Create(userId_);
    postProcessor->OnStateChanged(HdiStatus::HDI_DISCONNECTED);
    EXPECT_EQ(postProcessor->runningId_.empty(), true);
}

/*
 * Feature: Framework
 * Function: Test OnSessionDied with normal branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test OnSessionDied with normal branch
 */
HWTEST_F(DeferredPostPorcessorUnitTest, deferred_post_processor_unittest_019, TestSize.Level0)
{
    auto postProcessor = VideoPostProcessor::Create(userId_);
    postProcessor->runningId_.emplace(VIDEO_ID);
    postProcessor->OnSessionDied();
    EXPECT_EQ(postProcessor->runningId_.empty(), false);
}

/*
 * Feature: Framework
 * Function: Test GetIntent with normal branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetIntent with normal branch
 */
HWTEST_F(DeferredPostPorcessorUnitTest, deferred_post_processor_unittest_020, TestSize.Level0)
{
    auto postProcessor = VideoPostProcessor::Create(userId_);
    auto intent = postProcessor->GetIntent(HDI::Camera::V1_3::MediaStreamType::MEDIA_STREAM_TYPE_VIDEO);
    EXPECT_EQ(intent, HDI::Camera::V1_0::VIDEO);

    intent = postProcessor->GetIntent(HDI::Camera::V1_3::MediaStreamType::MEDIA_STREAM_TYPE_MAKER);
    EXPECT_EQ(intent, HDI::Camera::V1_0::CUSTOM);

    intent = postProcessor->GetIntent(HDI::Camera::V1_3::MediaStreamType::MEDIA_STREAM_TYPE_METADATA);
    EXPECT_EQ(intent, HDI::Camera::V1_0::PREVIEW);
}

/*
 * Feature: Framework
 * Function: Test ConnectService with normal branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test ConnectService with normal branch
 */
HWTEST_F(DeferredPostPorcessorUnitTest, deferred_post_processor_unittest_021, TestSize.Level0)
{
    auto postProcessor = VideoPostProcessor::Create(userId_);
    postProcessor->ConnectService();
    EXPECT_NE(postProcessor->serviceListener_, nullptr);
}

/*
 * Feature: Framework
 * Function: Test GetVideoSession with normal branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetVideoSession with normal branch
 */
HWTEST_F(DeferredPostPorcessorUnitTest, deferred_post_processor_unittest_022, TestSize.Level0)
{
    auto postProcessor = VideoPostProcessor::Create(userId_);
    auto session = sptr<MockVideoProcessSession>::MakeSptr();
    postProcessor->SetVideoSession(session.GetRefPtr());
    auto sessionV1_3 = postProcessor->GetVideoSession<VideoSessionV1_3>();
    EXPECT_NE(sessionV1_3, nullptr);
    postProcessor->SetVideoSession(nullptr);
}

/*
 * Feature: Framework
 * Function: Test GetVideoSession with normal branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetVideoSession with normal branch
 */
HWTEST_F(DeferredPostPorcessorUnitTest, deferred_post_processor_unittest_023, TestSize.Level0)
{
    auto postProcessor = VideoPostProcessor::Create(userId_);
    auto session = sptr<MockVideoProcessSession>::MakeSptr();
    postProcessor->SetVideoSession(session.GetRefPtr());
    auto sessionV1_5 = postProcessor->GetVideoSession<VideoSessionV1_5>();
    EXPECT_EQ(sessionV1_5, nullptr);
    postProcessor->SetVideoSession(nullptr);
}

/*
 * Feature: Framework
 * Function: Test VideoProcessListener with abnormal branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test VideoProcessListener with abnormal branch
 */
HWTEST_F(DeferredPostPorcessorUnitTest, deferred_post_processor_unittest_024, TestSize.Level1)
{
    int32_t userId = 1;
    OHOS::HDI::Camera::V1_2::ErrorCode errorCode = OHOS::HDI::Camera::V1_2::ErrorCode::ERROR_INVALID_ID;
    auto sharedResult = std::make_shared<VideoProcessResult>(userId);
    std::weak_ptr<VideoProcessResult> weakResultPtr = sharedResult;
    sptr<DeferredProcessing::VideoPostProcessor::VideoProcessListener> listener =
        new(std::nothrow) DeferredProcessing::VideoPostProcessor::VideoProcessListener(weakResultPtr);
    ASSERT_NE(listener, nullptr);

    std::string videoId = "test_id";
    sptr<HDI::Camera::V1_0::MapDataSequenceable> metadata = sptr<HDI::Camera::V1_0::MapDataSequenceable>::MakeSptr();
    listener->OnProcessDone(videoId);
    listener->OnProcessDone(videoId, metadata);
    metadata = nullptr;
    listener->OnProcessDone(videoId, metadata);
    EXPECT_EQ(listener->OnError(videoId, errorCode), 0);
    errorCode = OHOS::HDI::Camera::V1_2::ErrorCode::ERROR_PROCESS;
    EXPECT_EQ(listener->OnError(videoId, errorCode), 0);
    errorCode = OHOS::HDI::Camera::V1_2::ErrorCode::ERROR_TIMEOUT;
    EXPECT_EQ(listener->OnError(videoId, errorCode), 0);
    errorCode = OHOS::HDI::Camera::V1_2::ErrorCode::ERROR_HIGH_TEMPERATURE;
    EXPECT_EQ(listener->OnError(videoId, errorCode), 0);
    errorCode = OHOS::HDI::Camera::V1_2::ErrorCode::ERROR_ABNORMAL;
    EXPECT_EQ(listener->OnError(videoId, errorCode), 0);
    errorCode = OHOS::HDI::Camera::V1_2::ErrorCode::ERROR_ABORT;
    EXPECT_EQ(listener->OnError(videoId, errorCode), 0);
    errorCode = OHOS::HDI::Camera::V1_2::ErrorCode::ERROR_INVALID_ID;
    EXPECT_EQ(listener->OnError(videoId, errorCode), 0);

    OHOS::HDI::Camera::V1_2::SessionStatus status = OHOS::HDI::Camera::V1_2::SessionStatus::SESSION_STATUS_READY;
    EXPECT_EQ(listener->OnStatusChanged(status), 0);
    status = OHOS::HDI::Camera::V1_2::SessionStatus::SESSION_STATUS_READY_SPACE_LIMIT_REACHED;
    EXPECT_EQ(listener->OnStatusChanged(status), 0);
    status = OHOS::HDI::Camera::V1_2::SessionStatus::SESSSON_STATUS_NOT_READY_TEMPORARILY;
    EXPECT_EQ(listener->OnStatusChanged(status), 0);
    status = OHOS::HDI::Camera::V1_2::SessionStatus::SESSION_STATUS_NOT_READY_OVERHEAT;
    EXPECT_EQ(listener->OnStatusChanged(status), 0);
    status = OHOS::HDI::Camera::V1_2::SessionStatus::SESSION_STATUS_NOT_READY_PREEMPTED;
    EXPECT_EQ(listener->OnStatusChanged(status), 0);
    status = static_cast<OHOS::HDI::Camera::V1_2::SessionStatus>(10);
    EXPECT_EQ(listener->OnStatusChanged(status), 0);
}

/*
 * Feature: Framework
 * Function: Test Movie PrepareStreams with normal branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test Movie PrepareStreams with normal branch
 */
HWTEST_F(DeferredPostPorcessorUnitTest, deferred_post_processor_unittest_025, TestSize.Level0)
{
    auto postProcessor = VideoPostProcessor::Create(userId_);
    auto session = sptr<MockVideoProcessSession>::MakeSptr();
    postProcessor->sessionV1_3_ = session;
    DpsFdPtr inputFd = std::make_shared<DpsFd>(dup(srcFd_));
    DpsFdPtr outFd = std::make_shared<DpsFd>(dup(dtsFd_));
    int copyFd = open(VIDEO_PATH.c_str(), O_RDONLY);
    DpsFdPtr movieFd = std::make_shared<DpsFd>(dup(copyFd));
    DpsFdPtr movieCopyFd = std::make_shared<DpsFd>(dup(copyFd));
    close(copyFd);
    DeferredVideoJobPtr jobPtr = std::make_shared<DeferredVideoJob>(VIDEO_ID, inputFd, outFd, movieFd, movieCopyFd);
    auto mediaManagerProxy = MediaManagerProxy::CreateMediaManagerProxy();
    mediaManagerProxy->MpegAcquire(VIDEO_ID, inputFd, VIDEO_WIDTH, VIDEO_HIGHT);

    std::vector<StreamDescription> resultDescs {
        StreamDescription {
            .streamId = 0,
            .type = HDI::Camera::V1_3::MediaStreamType::MEDIA_STREAM_TYPE_VIDEO,
        },
        StreamDescription {
            .streamId = 1,
            .type = HDI::Camera::V1_3::MediaStreamType::MEDIA_STREAM_TYPE_MAKER,
        },
    };
    auto result = postProcessor->PrepareStreams(jobPtr);
    EXPECT_EQ(result.size(), 0);
    postProcessor->sessionV1_3_ = nullptr;
}

/*
 * Feature: Framework
 * Function: Test Movie ProcessRequest with normal branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test Movie ProcessRequest with normal branch
 */
HWTEST_F(DeferredPostPorcessorUnitTest, deferred_post_processor_unittest_026, TestSize.Level0)
{
    auto postProcessor = VideoPostProcessor::Create(userId_);
    auto session = sptr<MockVideoProcessSession>::MakeSptr();
    postProcessor->sessionV1_3_ = session;
    int copyFd = open(VIDEO_PATH.c_str(), O_RDONLY);
    DpsFdPtr inputFd = std::make_shared<DpsFd>(dup(srcFd_));
    DpsFdPtr outFd = std::make_shared<DpsFd>(dup(dtsFd_));
    close(copyFd);
    DeferredVideoJobPtr jobPtr = std::make_shared<DeferredVideoJob>(VIDEO_ID, inputFd, outFd, nullptr, nullptr);
    auto mediaManagerProxy = MediaManagerProxy::CreateMediaManagerProxy();
    mediaManagerProxy->MpegAcquire(VIDEO_ID, inputFd, VIDEO_WIDTH, VIDEO_HIGHT);

    std::vector<StreamDescription> resultDescs {
        StreamDescription {
            .streamId = 0,
            .type = HDI::Camera::V1_3::MediaStreamType::MEDIA_STREAM_TYPE_VIDEO,
        },
        StreamDescription {
            .streamId = 1,
            .type = HDI::Camera::V1_3::MediaStreamType::MEDIA_STREAM_TYPE_MAKER,
        },
    };
    EventsInfo::GetInstance().cameraState_ = SYSTEM_CAMERA_CLOSED;
    postProcessor->ProcessRequest(VIDEO_ID, resultDescs, mediaManagerProxy);
    EXPECT_EQ(postProcessor->runningId_.size(), 1);
    postProcessor->sessionV1_3_ = nullptr;
}

/*
 * Feature: Framework
 * Function: Test Movie ProcessRequest with abnormal branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test Movie ProcessRequest with abnormal branch
 */
HWTEST_F(DeferredPostPorcessorUnitTest, deferred_post_processor_unittest_027, TestSize.Level0)
{
    auto postProcessor = VideoPostProcessor::Create(userId_);
    std::vector<StreamDescription> resultDescs {
        StreamDescription {
            .streamId = 0,
            .type = HDI::Camera::V1_3::MediaStreamType::MEDIA_STREAM_TYPE_VIDEO,
        },
        StreamDescription {
            .streamId = 1,
            .type = HDI::Camera::V1_3::MediaStreamType::MEDIA_STREAM_TYPE_MAKER,
        },
    };
    postProcessor->ProcessRequest(VIDEO_ID, resultDescs, nullptr);
    EXPECT_EQ(postProcessor->runningId_.size(), 0);
}

/*
 * Feature: Framework
 * Function: Test Movie ProcessRequest with abnormal branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test Movie ProcessRequest with abnormal branch
 */
HWTEST_F(DeferredPostPorcessorUnitTest, deferred_post_processor_unittest_028, TestSize.Level0)
{
    auto postProcessor = VideoPostProcessor::Create(userId_);
    DpsFdPtr inputFd = std::make_shared<DpsFd>(dup(srcFd_));
    auto mediaManagerProxy = MediaManagerProxy::CreateMediaManagerProxy();
    mediaManagerProxy->MpegAcquire(VIDEO_ID, inputFd, VIDEO_WIDTH, VIDEO_HIGHT);
    std::vector<StreamDescription> resultDescs;
    postProcessor->ProcessRequest(VIDEO_ID, resultDescs, mediaManagerProxy);
    EXPECT_EQ(postProcessor->runningId_.size(), 0);
}

/*
 * Feature: Framework
 * Function: Test Movie ProcessRequest with abnormal branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test Movie ProcessRequest with abnormal branch
 */
HWTEST_F(DeferredPostPorcessorUnitTest, deferred_post_processor_unittest_029, TestSize.Level0)
{
    auto postProcessor = VideoPostProcessor::Create(userId_);
    auto session = sptr<MockVideoProcessSession>::MakeSptr();
    postProcessor->sessionV1_3_ = session;
    DpsFdPtr inputFd = std::make_shared<DpsFd>(dup(srcFd_));
    auto mediaManagerProxy = MediaManagerProxy::CreateMediaManagerProxy();
    mediaManagerProxy->MpegAcquire(VIDEO_ID, inputFd, VIDEO_WIDTH, VIDEO_HIGHT);
    std::vector<StreamDescription> resultDescs;
    postProcessor->ProcessRequest(VIDEO_ID, resultDescs, mediaManagerProxy);
    EXPECT_EQ(postProcessor->runningId_.size(), 0);
    postProcessor->sessionV1_3_ = nullptr;
}

/*
 * Feature: Framework
 * Function: Test Movie ProcessRequest with abnormal branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test Movie ProcessRequest with abnormal branch
 */
HWTEST_F(DeferredPostPorcessorUnitTest, deferred_post_processor_unittest_030, TestSize.Level0)
{
    auto postProcessor = VideoPostProcessor::Create(userId_);
    auto session = sptr<MockVideoProcessSession>::MakeSptr();
    postProcessor->sessionV1_3_ = session;
    DpsFdPtr inputFd = std::make_shared<DpsFd>(dup(srcFd_));
    auto mediaManagerProxy = MediaManagerProxy::CreateMediaManagerProxy();
    mediaManagerProxy->MpegAcquire(VIDEO_ID, inputFd, VIDEO_WIDTH, VIDEO_HIGHT);
    std::vector<StreamDescription> resultDescs {
        StreamDescription {
            .streamId = 0,
            .type = HDI::Camera::V1_3::MediaStreamType::MEDIA_STREAM_TYPE_VIDEO,
        },
        StreamDescription {
            .streamId = 1,
            .type = HDI::Camera::V1_3::MediaStreamType::MEDIA_STREAM_TYPE_MAKER,
        },
    };
    EventsInfo::GetInstance().cameraState_ = NORMAL_CAMERA_OPEN;
    postProcessor->ProcessRequest(VIDEO_ID, resultDescs, mediaManagerProxy);
    EXPECT_EQ(postProcessor->runningId_.size(), 0);
    postProcessor->sessionV1_3_ = nullptr;
    EventsInfo::GetInstance().cameraState_ = SYSTEM_CAMERA_CLOSED;
}

/*
 * Feature: Framework
 * Function: Test Movie ProcessRequest with abnormal branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test Movie ProcessRequest with abnormal branch
 */
HWTEST_F(DeferredPostPorcessorUnitTest, deferred_post_processor_unittest_031, TestSize.Level0)
{
    auto postProcessor = VideoPostProcessor::Create(userId_);
    auto session = sptr<MockVideoProcessSession>::MakeSptr();
    postProcessor->sessionV1_3_ = session;
    DpsFdPtr inputFd = std::make_shared<DpsFd>(dup(srcFd_));
    auto mediaManagerProxy = MediaManagerProxy::CreateMediaManagerProxy();
    mediaManagerProxy->MpegAcquire(VIDEO_ID, inputFd, VIDEO_WIDTH, VIDEO_HIGHT);
    std::vector<StreamDescription> resultDescs {
        StreamDescription {
            .streamId = 0,
            .type = HDI::Camera::V1_3::MediaStreamType::MEDIA_STREAM_TYPE_VIDEO,
        },
        StreamDescription {
            .streamId = 1,
            .type = HDI::Camera::V1_3::MediaStreamType::MEDIA_STREAM_TYPE_MAKER,
        },
    };
    EventsInfo::GetInstance().cameraState_ = SYSTEM_CAMERA_CLOSED;
    EXPECT_CALL(*session, CreateStreams).WillOnce(Return(ERROR));
    postProcessor->ProcessRequest(VIDEO_ID, resultDescs, mediaManagerProxy);
    EXPECT_EQ(postProcessor->runningId_.size(), 0);
    postProcessor->sessionV1_3_ = nullptr;
}

/*
 * Feature: Framework
 * Function: Test Movie ProcessRequest with abnormal branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test Movie ProcessRequest with abnormal branch
 */
HWTEST_F(DeferredPostPorcessorUnitTest, deferred_post_processor_unittest_032, TestSize.Level0)
{
    auto postProcessor = VideoPostProcessor::Create(userId_);
    auto session = sptr<MockVideoProcessSession>::MakeSptr();
    postProcessor->sessionV1_3_ = session;
    DpsFdPtr inputFd = std::make_shared<DpsFd>(dup(srcFd_));
    auto mediaManagerProxy = MediaManagerProxy::CreateMediaManagerProxy();
    mediaManagerProxy->MpegAcquire(VIDEO_ID, inputFd, VIDEO_WIDTH, VIDEO_HIGHT);
    std::vector<StreamDescription> resultDescs {
        StreamDescription {
            .streamId = 0,
            .type = HDI::Camera::V1_3::MediaStreamType::MEDIA_STREAM_TYPE_VIDEO,
        },
        StreamDescription {
            .streamId = 1,
            .type = HDI::Camera::V1_3::MediaStreamType::MEDIA_STREAM_TYPE_MAKER,
        },
    };
    EventsInfo::GetInstance().cameraState_ = SYSTEM_CAMERA_CLOSED;
    EXPECT_CALL(*session, CommitStreams).WillOnce(Return(ERROR));
    postProcessor->ProcessRequest(VIDEO_ID, resultDescs, mediaManagerProxy);
    EXPECT_EQ(postProcessor->runningId_.size(), 0);
    postProcessor->sessionV1_3_ = nullptr;
}

/*
 * Feature: Framework
 * Function: Test Movie ProcessRequest with abnormal branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test Movie ProcessRequest with abnormal branch
 */
HWTEST_F(DeferredPostPorcessorUnitTest, deferred_post_processor_unittest_033, TestSize.Level0)
{
    auto postProcessor = VideoPostProcessor::Create(userId_);
    auto session = sptr<MockVideoProcessSession>::MakeSptr();
    postProcessor->sessionV1_3_ = session;
    DpsFdPtr inputFd = std::make_shared<DpsFd>(dup(srcFd_));
    auto mediaManagerProxy = MediaManagerProxy::CreateMediaManagerProxy();
    mediaManagerProxy->MpegAcquire(VIDEO_ID, inputFd, VIDEO_WIDTH, VIDEO_HIGHT);
    std::vector<StreamDescription> resultDescs {
        StreamDescription {
            .streamId = 0,
            .type = HDI::Camera::V1_3::MediaStreamType::MEDIA_STREAM_TYPE_VIDEO,
        },
        StreamDescription {
            .streamId = 1,
            .type = HDI::Camera::V1_3::MediaStreamType::MEDIA_STREAM_TYPE_MAKER,
        },
    };
    EventsInfo::GetInstance().cameraState_ = SYSTEM_CAMERA_CLOSED;
    EXPECT_CALL(*session, ProcessVideo).WillOnce(Return(ERROR));
    postProcessor->ProcessRequest(VIDEO_ID, resultDescs, mediaManagerProxy);
    EXPECT_EQ(postProcessor->runningId_.size(), 0);
    postProcessor->sessionV1_3_ = nullptr;
}

/*
 * Feature: Framework
 * Function: Test Executing with abnormal ImageInfo
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test Executing with abnormal ImageInfo
 */
HWTEST_F(DeferredPostPorcessorUnitTest, deferred_post_processor_unittest_034, TestSize.Level0)
{
    int32_t dataSize = 1024;
    bool isHighQuality = true;
    uint32_t cloudFlag = 0x1234;
    uint32_t captureFlag = 123;
    DpsMetadata metaData;
    metaData.Set("cloudFlag", cloudFlag);
    metaData.Set("captureFlag", captureFlag);
    ImageInfo imageInfo(dataSize, isHighQuality, cloudFlag, captureFlag, metaData);
    EXPECT_EQ(imageInfo.dataSize_, dataSize);
    EXPECT_EQ(imageInfo.isHighQuality_, isHighQuality);
    EXPECT_EQ(imageInfo.cloudFlag_, cloudFlag);
    EXPECT_EQ(imageInfo.captureFlag_, captureFlag);
    uint32_t val1;
    imageInfo.dpsMetaData_.Get("captureFlag", val1);
    EXPECT_EQ(val1, captureFlag);
    uint32_t val2;
    imageInfo.dpsMetaData_.Get("cloudFlag", val2);
    EXPECT_EQ(val2, cloudFlag);
}
} // CameraStandard
} // OHOS