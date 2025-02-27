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
#include "photo_post_processor.h"
#include "basic_definitions.h"
#include "accesstoken_kit.h"
#include "ipc_skeleton.h"
#include "nativetoken_kit.h"
#include "os_account_manager.h"
#include "photo_process_command.h"
#include "service_died_command.h"
#include "token_setproc.h"
#include "video_process_command.h"
#include "dp_utils.h"
#include "iimage_process_callbacks.h"
#include "v1_3/iimage_process_callback.h"
#include "dps.h"

using namespace testing::ext;
using namespace OHOS::CameraStandard::DeferredProcessing;

namespace OHOS {
namespace CameraStandard {

static constexpr int32_t BUFFER_HANDLE_RESERVE_TEST_SIZE = 16;
constexpr int VIDEO_SOURCE_FD = 1;
constexpr int VIDEO_DESTINATION_FD = 2;

void DeferredPostPorcessorUnitTest::SetUpTestCase(void) {}

void DeferredPostPorcessorUnitTest::TearDownTestCase(void) {}

void DeferredPostPorcessorUnitTest::SetUp()
{
    NativeAuthorization();
}

void DeferredPostPorcessorUnitTest::TearDown() {}

void DeferredPostPorcessorUnitTest::NativeAuthorization()
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
    SetSelfTokenID(tokenId_);
    OHOS::Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
}

class DeferredPhotoProcessorCallbacks : public IImageProcessCallbacks {
public:
    explicit DeferredPhotoProcessorCallbacks() {}

    ~DeferredPhotoProcessorCallbacks() override {}

    void OnProcessDone(const int32_t userId, const std::string& imageId,
        const std::shared_ptr<BufferInfo>& bufferInfo) override {}

    void OnProcessDoneExt(int userId, const std::string& imageId,
        const std::shared_ptr<BufferInfoExt>& bufferInfo) override {}

    void OnError(const int userId, const std::string& imageId, DpsError errorCode) override {}

    void OnStateChanged(const int32_t userId, DpsStatus statusCode) override {}
};

class PhotoPostProcessor::PhotoProcessListener : public OHOS::HDI::Camera::V1_3::IImageProcessCallback {
public:
    explicit PhotoProcessListener(const int32_t userId, const std::weak_ptr<PhotoProcessResult>& processResult)
        : userId_(userId), processResult_(processResult)
    {
        DP_DEBUG_LOG("entered.");
    }

    int32_t OnProcessDone(const std::string& imageId, const OHOS::HDI::Camera::V1_2::ImageBufferInfo& buffer) override;
    int32_t OnProcessDoneExt(const std::string& imageId,
        const OHOS::HDI::Camera::V1_3::ImageBufferInfoExt& buffer) override;
    int32_t OnError(const std::string& imageId,  OHOS::HDI::Camera::V1_2::ErrorCode errorCode) override;
    int32_t OnStatusChanged(OHOS::HDI::Camera::V1_2::SessionStatus status) override;

private:
    void ReportEvent(const std::string& imageId);
    int32_t ProcessBufferInfo(const std::string& imageId, const OHOS::HDI::Camera::V1_2::ImageBufferInfo& buffer);
    int32_t ProcessBufferInfoExt(const std::string& imageId,
        const OHOS::HDI::Camera::V1_3::ImageBufferInfoExt& buffer);
    std::shared_ptr<Media::Picture> AssemblePicture(const OHOS::HDI::Camera::V1_3::ImageBufferInfoExt& buffer);

    const int32_t userId_;
    std::weak_ptr<PhotoProcessResult> processResult_;
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

/*
 * Feature: Framework
 * Function: Test OnError with abnormal branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test OnError with abnormal branch
 */
HWTEST_F(DeferredPostPorcessorUnitTest, deferred_post_processor_unittest_002, TestSize.Level0)
{
    auto postProcessor = CreateShared<VideoPostProcessor>(userId_);
    ASSERT_NE(postProcessor, nullptr);
    postProcessor->Initialize();
    ExecutionMode selectedExecutionMode = static_cast<ExecutionMode>(VIDEO_SOURCE_FD);
    postProcessor->SetExecutionMode(selectedExecutionMode);
    postProcessor->SetDefaultExecutionMode();
    std::vector<std::string> testStrings = {"test1", "test2"};
    uint8_t randomNum = 1;
    std::string videoId(testStrings[randomNum % testStrings.size()]);
    auto srcFd = 1;
    auto dstFd = 1;
    postProcessor->copyFileByFd(srcFd, dstFd);
    auto isAutoSuspend = true;
    std::string videoId_(testStrings[randomNum % testStrings.size()]);
    sptr<IPCFileDescriptor> srcFd_ = sptr<IPCFileDescriptor>::MakeSptr(VIDEO_SOURCE_FD);
    sptr<IPCFileDescriptor> dstFd_ = sptr<IPCFileDescriptor>::MakeSptr(VIDEO_DESTINATION_FD);
    DeferredVideoJobPtr jobPtr = std::make_shared<DeferredVideoJob>(videoId_, srcFd_, dstFd_);
    std::shared_ptr<DeferredVideoWork> work =
        std::make_shared<DeferredVideoWork>(jobPtr, selectedExecutionMode, isAutoSuspend);
    postProcessor->StartTimer(videoId, work);
    DeferredProcessing::DPS_Initialize();
    EXPECT_NE(DeferredProcessing::DPS_GetSchedulerManager(), nullptr);
    postProcessor->OnError(videoId, DpsError::DPS_ERROR_VIDEO_PROC_INTERRUPTED);
    postProcessor->StartTimer(videoId, work);
    postProcessor->OnError(videoId, DpsError::DPS_ERROR_SESSION_SYNC_NEEDED);
}

/*
 * Feature: Framework
 * Function: Test GetIntent with abnormal branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetIntent with abnormal branch
 */
HWTEST_F(DeferredPostPorcessorUnitTest, deferred_post_processor_unittest_003, TestSize.Level0)
{
    auto postProcessor = CreateShared<VideoPostProcessor>(userId_);
    ASSERT_NE(postProcessor, nullptr);
    postProcessor->Initialize();
    HDI::Camera::V1_0::StreamIntent streamIntent = postProcessor->GetIntent(HDI::Camera::V1_3::MEDIA_STREAM_TYPE_MAKER);
    EXPECT_EQ(streamIntent, HDI::Camera::V1_0::CUSTOM);
    streamIntent = postProcessor->GetIntent(HDI::Camera::V1_3::MEDIA_STREAM_TYPE_VIDEO);
    EXPECT_EQ(streamIntent, HDI::Camera::V1_0::VIDEO);
    streamIntent = postProcessor->GetIntent(static_cast<HDI::Camera::V1_3::MediaStreamType>(-1));
    EXPECT_EQ(streamIntent, HDI::Camera::V1_0::PREVIEW);
}

/*
 * Feature: Framework
 * Function: Test ProcessStream with abnormal branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test ProcessStream with abnormal branch
 */
HWTEST_F(DeferredPostPorcessorUnitTest, deferred_post_processor_unittest_004, TestSize.Level0)
{
    auto postProcessor = CreateShared<VideoPostProcessor>(userId_);
    ASSERT_NE(postProcessor, nullptr);
    StreamDescription steamInfo;
    postProcessor->mpegManager_ = std::make_shared<MpegManager>();
    ASSERT_NE(postProcessor->mpegManager_, nullptr);
    steamInfo.type = HDI::Camera::V1_3::MEDIA_STREAM_TYPE_VIDEO;
    bool result = postProcessor->ProcessStream(steamInfo);
    steamInfo.type = HDI::Camera::V1_3::MEDIA_STREAM_TYPE_MAKER;
    result = postProcessor->ProcessStream(steamInfo);
    EXPECT_FALSE(result);
}

/*
 * Feature: Framework
 * Function: Test PhotoPostProcessor with abnormal branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test PhotoPostProcessor with abnormal branch
 */
HWTEST_F(DeferredPostPorcessorUnitTest, deferred_post_processor_unittest_005, TestSize.Level0)
{
    auto postProcessor = CreateShared<PhotoPostProcessor>(userId_);
    ASSERT_NE(postProcessor, nullptr);
    std::string imageId = "testImageId";
    postProcessor->OnError(imageId, DpsError::DPS_ERROR_IMAGE_PROC_FAILED);
    EXPECT_EQ(postProcessor->consecutiveTimeoutCount_, 0);
    postProcessor->OnError(imageId, DpsError::DPS_ERROR_IMAGE_PROC_TIMEOUT);
    EXPECT_EQ(postProcessor->consecutiveTimeoutCount_, 1);
    postProcessor->consecutiveTimeoutCount_ = 10;
    postProcessor->OnError(imageId, DpsError::DPS_ERROR_IMAGE_PROC_TIMEOUT);
    EXPECT_EQ(postProcessor->consecutiveTimeoutCount_, 11);
    postProcessor->OnError(imageId, DpsError::DPS_ERROR_IMAGE_PROC_FAILED);
    EXPECT_EQ(postProcessor->consecutiveTimeoutCount_, 0);
}

/*
 * Feature: Framework
 * Function: Test PhotoProcessListener with abnormal branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test PhotoProcessListener with abnormal branch
 */
HWTEST_F(DeferredPostPorcessorUnitTest, deferred_post_processor_unittest_006, TestSize.Level0)
{
    int32_t userId = 1;
    OHOS::HDI::Camera::V1_2::ErrorCode errorCode = OHOS::HDI::Camera::V1_2::ErrorCode::ERROR_INVALID_ID;
    std::shared_ptr<PhotoProcessResult> sharedResult = std::make_shared<PhotoProcessResult>(userId);
    std::weak_ptr<PhotoProcessResult> weakResultPtr = sharedResult;
    sptr<DeferredProcessing::PhotoPostProcessor::PhotoProcessListener> listener =
        new(std::nothrow) DeferredProcessing::PhotoPostProcessor::PhotoProcessListener(userId, weakResultPtr);
    ASSERT_NE(listener, nullptr);

    std::string imageId = "test_id";
    OHOS::HDI::Camera::V1_2::ImageBufferInfo buffer;
    size_t handleSize = sizeof(BufferHandle) + (sizeof(int32_t) * (BUFFER_HANDLE_RESERVE_TEST_SIZE * 2));
    BufferHandle *handle = static_cast<BufferHandle *>(malloc(handleSize));
    buffer.imageHandle = new(std::nothrow) HDI::Camera::V1_0::BufferHandleSequenceable(*handle);
    buffer.metadata = new(std::nothrow) HDI::Camera::V1_0::MapDataSequenceable();
    listener->OnProcessDone(imageId, buffer);
    buffer.metadata = nullptr;
    listener->OnProcessDone(imageId, buffer);
    EXPECT_EQ(listener->OnError(imageId, errorCode), 0);
    errorCode = OHOS::HDI::Camera::V1_2::ErrorCode::ERROR_PROCESS;
    EXPECT_EQ(listener->OnError(imageId, errorCode), 0);
    errorCode = OHOS::HDI::Camera::V1_2::ErrorCode::ERROR_TIMEOUT;
    EXPECT_EQ(listener->OnError(imageId, errorCode), 0);
    errorCode = OHOS::HDI::Camera::V1_2::ErrorCode::ERROR_HIGH_TEMPERATURE;
    EXPECT_EQ(listener->OnError(imageId, errorCode), 0);
    errorCode = OHOS::HDI::Camera::V1_2::ErrorCode::ERROR_ABNORMAL;
    EXPECT_EQ(listener->OnError(imageId, errorCode), 0);
    errorCode = OHOS::HDI::Camera::V1_2::ErrorCode::ERROR_ABORT;
    EXPECT_EQ(listener->OnError(imageId, errorCode), 0);
    errorCode = static_cast<OHOS::HDI::Camera::V1_2::ErrorCode>(10);
    EXPECT_EQ(listener->OnError(imageId, errorCode), 0);

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
 * Function: Test AssemblePicture with abnormal branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test AssemblePicture with abnormal branch
 */
HWTEST_F(DeferredPostPorcessorUnitTest, deferred_post_processor_unittest_007, TestSize.Level0)
{
    int32_t userId = 1;
    std::string imageId = "testImageId";
    std::shared_ptr<PhotoProcessResult> sharedResult = std::make_shared<PhotoProcessResult>(userId);
    std::weak_ptr<PhotoProcessResult> weakResultPtr = sharedResult;
    sptr<DeferredProcessing::PhotoPostProcessor::PhotoProcessListener> listener =
        new(std::nothrow) DeferredProcessing::PhotoPostProcessor::PhotoProcessListener(userId, weakResultPtr);
    ASSERT_NE(listener, nullptr);

    OHOS::HDI::Camera::V1_3::ImageBufferInfoExt buffer;
    size_t handleSize = sizeof(BufferHandle) + (sizeof(int32_t) * (BUFFER_HANDLE_RESERVE_TEST_SIZE * 2));
    BufferHandle *handle = static_cast<BufferHandle *>(malloc(handleSize));
    buffer.imageHandle = new(std::nothrow) HDI::Camera::V1_0::BufferHandleSequenceable(*handle);
    buffer.exifHandle = new(std::nothrow) HDI::Camera::V1_0::BufferHandleSequenceable(*handle);
    buffer.metadata = new(std::nothrow) HDI::Camera::V1_0::MapDataSequenceable();
    buffer.isExifValid = true;
    listener->ProcessBufferInfoExt(imageId, buffer);
    ASSERT_NE(listener->AssemblePicture(buffer), nullptr);
    buffer.isExifValid = false;
    ASSERT_NE(listener->AssemblePicture(buffer), nullptr);
    buffer.metadata = nullptr;
    listener->ProcessBufferInfoExt(imageId, buffer);
    ASSERT_NE(listener->AssemblePicture(buffer), nullptr);
    buffer.isExifValid = true;
    ASSERT_NE(listener->AssemblePicture(buffer), nullptr);
    free(handle);
}

/*
 * Feature: Framework
 * Function: Test OnError OnStatusChanged with abnormal branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test OnError OnStatusChanged with abnormal branch
 */
HWTEST_F(DeferredPostPorcessorUnitTest, deferred_post_processor_unittest_008, TestSize.Level0)
{
    auto postProcessor = CreateShared<PhotoPostProcessor>(userId_);
    ASSERT_NE(postProcessor, nullptr);
    int32_t userId = 1;
    std::string imageId = "testImageId";
    std::shared_ptr<PhotoProcessResult> sharedResult = std::make_shared<PhotoProcessResult>(userId);
    std::weak_ptr<PhotoProcessResult> weakResultPtr = sharedResult;
    sptr<DeferredProcessing::PhotoPostProcessor::PhotoProcessListener> listener =
        new(std::nothrow) DeferredProcessing::PhotoPostProcessor::PhotoProcessListener(userId, weakResultPtr);
    ASSERT_NE(listener, nullptr);
    postProcessor->ProcessImage(imageId);
    OHOS::HDI::Camera::V1_2::ErrorCode errorCode = OHOS::HDI::Camera::V1_2::ErrorCode::ERROR_INVALID_ID;
    OHOS::HDI::Camera::V1_2::SessionStatus status = OHOS::HDI::Camera::V1_2::SessionStatus::SESSION_STATUS_READY;
    sharedResult.reset();
    std::shared_ptr<BufferInfo> bufferInfo = std::make_shared<BufferInfo>(nullptr, 0, true, true);
    std::shared_ptr<BufferInfoExt> bufferInfoExt = std::make_shared<BufferInfoExt>(nullptr, 0, true, true);
    auto callback = std::make_shared<DeferredPhotoProcessorCallbacks>();
    ASSERT_NE(callback, nullptr);
    postProcessor->callback_ = callback;
    postProcessor->OnProcessDone(imageId, bufferInfo);
    postProcessor->OnProcessDoneExt(imageId, bufferInfoExt);
    postProcessor->OnError(imageId, DpsError::DPS_ERROR_IMAGE_PROC_TIMEOUT);
    callback.reset();
    postProcessor->OnProcessDone(imageId, bufferInfo);
    postProcessor->OnProcessDoneExt(imageId, bufferInfoExt);
    postProcessor->OnError(imageId, DpsError::DPS_ERROR_IMAGE_PROC_TIMEOUT);
    EXPECT_EQ(listener->OnError(imageId, errorCode), 0);
    EXPECT_EQ(listener->OnStatusChanged(status), 0);
}

/*
 * Feature: Framework
 * Function: Test StopMpeg with abnormal branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test StopMpeg with abnormal branch
 */
HWTEST_F(DeferredPostPorcessorUnitTest, deferred_post_processor_unittest_009, TestSize.Level0)
{
    auto postProcessor = CreateShared<VideoPostProcessor>(userId_);
    ASSERT_NE(postProcessor, nullptr);
    std::string imageId = "testImageId";
    EXPECT_FALSE(postProcessor->StartMpeg(imageId, nullptr));
}

/*
 * Feature: Framework
 * Function: Test Executing with abnormal branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test Executing with abnormal branch
 */
HWTEST_F(DeferredPostPorcessorUnitTest, deferred_post_processor_unittest_010, TestSize.Level0)
{
    std::string imageId = "testImageId";
    auto successCommand = CreateShared<PhotoProcessSuccessCommand>(userId_, imageId, nullptr);
    EXPECT_EQ(successCommand->Executing(), DP_ERR);
    auto successExtCommand = CreateShared<PhotoProcessSuccessExtCommand>(userId_, imageId, nullptr);
    EXPECT_EQ(successExtCommand->Executing(), DP_ERR);
    DpsError errorCode = DpsError::DPS_ERROR_IMAGE_PROC_TIMEOUT;
    auto failedCommand = CreateShared<PhotoProcessFailedCommand>(userId_, imageId, errorCode);
    EXPECT_EQ(failedCommand->Executing(), DP_ERR);
    auto photoDiedCommand = CreateShared<PhotoDiedCommand>(userId_);
    EXPECT_EQ(photoDiedCommand->Executing(), DP_NULL_POINTER);
    auto videoDiedCommand = CreateShared<VideoDiedCommand>(userId_);
    EXPECT_EQ(videoDiedCommand->Executing(), DP_NULL_POINTER);
    auto videoProcessSuccessCommand = CreateShared<VideoProcessSuccessCommand>(userId_, imageId);
    EXPECT_EQ(videoProcessSuccessCommand->Executing(), DP_ERR);
    auto videoProcessFailedCommand = CreateShared<VideoProcessFailedCommand>(userId_, imageId, errorCode);
    EXPECT_EQ(videoProcessFailedCommand->Executing(), DP_ERR);
}
} // CameraStandard
} // OHOS