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

#include "video_output_unittest.h"

#include "gtest/gtest.h"
#include <cstdint>
#include <memory>
#include <vector>

#include "access_token.h"
#include "accesstoken_kit.h"
#include "camera_error_code.h"
#include "camera_log.h"
#include "camera_manager.h"
#include "camera_util.h"
#include "capture_output.h"
#include "capture_session.h"
#include "gmock/gmock.h"
#include "input/camera_input.h"
#include "ipc_skeleton.h"
#include "nativetoken_kit.h"
#include "surface.h"
#include "test_common.h"
#include "token_setproc.h"
#include "os_account_manager.h"
#include "video_output_impl.h"
#include "test_token.h"

using namespace testing::ext;
using ::testing::A;
using ::testing::InSequence;
using ::testing::Mock;
using ::testing::Return;
using ::testing::_;

namespace OHOS {
namespace CameraStandard {
using namespace OHOS::HDI::Camera::V1_1;

void CameraVedioOutputUnit::SetUpTestCase(void)
{
    ASSERT_TRUE(TestToken().GetAllCameraPermission());
}

void CameraVedioOutputUnit::TearDownTestCase(void) {}

void CameraVedioOutputUnit::SetUp()
{
    cameraManager_ = CameraManager::GetInstance();
}

void CameraVedioOutputUnit::TearDown()
{
    cameraManager_ = nullptr;
}

sptr<CaptureOutput> CameraVedioOutputUnit::CreateVideoOutput()
{
    std::vector<VideoProfile> profile = {};
    if (!cameraManager_) {
        return nullptr;
    }
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();
    if (cameras.empty()) {
        return nullptr;
    }
    auto outputCapability = cameraManager_->GetSupportedOutputCapability(cameras[0], 0);
    if (!outputCapability) {
        return nullptr;
    }

    profile = outputCapability->GetVideoProfiles();
    if (profile.empty()) {
        return nullptr;
    }

    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    if (surface == nullptr) {
        return nullptr;
    }
    return cameraManager_->CreateVideoOutput(profile[0], surface);
}

/*
 * Feature: Framework
 * Function: Test videooutput when videoOutput
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test videooutput when videoOutput
 */
HWTEST_F(CameraVedioOutputUnit, video_output_unittest_001, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();
    ASSERT_FALSE(cameras.empty());
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }

    sptr<CaptureOutput> output = CreateVideoOutput();
    ASSERT_NE(output, nullptr);
    sptr<VideoOutput> videoOutput = (sptr<VideoOutput>&)output;

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(output), 0);
    EXPECT_EQ(session->CommitConfig(), 0);
    EXPECT_EQ(session->Start(), 0);

    videoOutput->stream_ = nullptr;
    int32_t ret = videoOutput->CreateStream();
    EXPECT_EQ(ret, CameraErrorCode::SUCCESS);
    ret = videoOutput->Start();
    EXPECT_NE(ret, CameraErrorCode::CONFLICT_CAMERA);
    ret = videoOutput->Pause();
    EXPECT_EQ(ret, CAMERA_INVALID_STATE);
    ret = videoOutput->Resume();
    EXPECT_EQ(ret, CameraErrorCode::SERVICE_FATL_ERROR);
    ret = videoOutput->Stop();
    EXPECT_EQ(ret, CameraErrorCode::SERVICE_FATL_ERROR);
    ret = videoOutput->Release();
    EXPECT_EQ(ret, 0);

    EXPECT_EQ(input->Release(), 0);
    session->Stop();
    EXPECT_EQ(session->Release(), 0);
}

/*
 * Feature: Framework
 * Function: Test start in videoOutput
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test start in videoOutput
 */
HWTEST_F(CameraVedioOutputUnit, video_output_unittest_002, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();
    ASSERT_FALSE(cameras.empty());
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }

    sptr<CaptureOutput> output = CreateVideoOutput();
    ASSERT_NE(output, nullptr);
    sptr<VideoOutput> videoOutput = (sptr<VideoOutput>&)output;

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(output), 0);
    EXPECT_EQ(session->CommitConfig(), 0);
    EXPECT_EQ(session->Start(), 0);

    videoOutput->stream_ = nullptr;
    int32_t ret = videoOutput->CreateStream();
    EXPECT_EQ(ret, CameraErrorCode::SUCCESS);

    wptr<IStreamCommon> stream_;
    sptr<IStreamCommon> stream = stream_.promote();
    videoOutput->SetStream(stream);

    ret = videoOutput->Start();
    EXPECT_NE(ret, CameraErrorCode::CONFLICT_CAMERA);

    int32_t minFrameRate = 200;
    int32_t maxFrameRate = 300;
    videoOutput->SetFrameRateRange(minFrameRate, maxFrameRate);
    ret = videoOutput->Start();
    EXPECT_NE(ret, CameraErrorCode::CONFLICT_CAMERA);

    minFrameRate = 100;
    videoOutput->SetFrameRateRange(minFrameRate, maxFrameRate);
    ret = videoOutput->Start();
    EXPECT_NE(ret, CameraErrorCode::CONFLICT_CAMERA);

    EXPECT_EQ(input->Release(), 0);
    EXPECT_EQ(session->Release(), 0);
}

/*
 * Feature: Framework
 * Function: Test stop in videoOutput
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test stop in videoOutput
 */
HWTEST_F(CameraVedioOutputUnit, video_output_unittest_003, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();
    ASSERT_FALSE(cameras.empty());
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }

    sptr<CaptureOutput> output = CreateVideoOutput();
    ASSERT_NE(output, nullptr);
    sptr<VideoOutput> videoOutput = (sptr<VideoOutput>&)output;

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(output), 0);
    EXPECT_EQ(session->CommitConfig(), 0);
    EXPECT_EQ(session->Start(), 0);

    videoOutput->stream_ = nullptr;
    int32_t ret = videoOutput->CreateStream();
    EXPECT_EQ(ret, CameraErrorCode::SUCCESS);

    wptr<IStreamCommon> stream_;
    sptr<IStreamCommon> stream = stream_.promote();
    videoOutput->SetStream(stream);

    ret = videoOutput->Start();
    EXPECT_NE(ret, CameraErrorCode::CONFLICT_CAMERA);
    ret = videoOutput->Stop();
    EXPECT_EQ(ret, CameraErrorCode::SERVICE_FATL_ERROR);

    int32_t minFrameRate = 200;
    int32_t maxFrameRate = 300;
    videoOutput->SetFrameRateRange(minFrameRate, maxFrameRate);
    ret = videoOutput->Stop();
    EXPECT_EQ(ret, CameraErrorCode::SERVICE_FATL_ERROR);

    minFrameRate = 100;
    videoOutput->SetFrameRateRange(minFrameRate, maxFrameRate);
    ret = videoOutput->Stop();
    EXPECT_EQ(ret, CameraErrorCode::SERVICE_FATL_ERROR);

    EXPECT_EQ(input->Release(), 0);
    EXPECT_EQ(session->Release(), 0);
}

/*
 * Feature: Framework
 * Function: Test IsMirrorSupported in videoOutput
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test IsMirrorSupported in videoOutput
 */
HWTEST_F(CameraVedioOutputUnit, video_output_unittest_004, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();
    ASSERT_FALSE(cameras.empty());
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }

    sptr<CaptureOutput> output = CreateVideoOutput();
    ASSERT_NE(output, nullptr);
    sptr<VideoOutput> videoOutput = (sptr<VideoOutput>&)output;

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(output), 0);
    EXPECT_EQ(session->CommitConfig(), 0);
    EXPECT_EQ(session->Start(), 0);

    bool ret = videoOutput->IsMirrorSupported();
    EXPECT_EQ(ret, false);

    EXPECT_EQ(input->Release(), 0);
    EXPECT_EQ(session->Release(), 0);
}

/*
 * Feature: Framework
 * Function: Test GetSupportedVideoMetaTypes in videoOutput
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetSupportedVideoMetaTypes in videoOutput
 */
HWTEST_F(CameraVedioOutputUnit, video_output_unittest_005, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();
    ASSERT_FALSE(cameras.empty());
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }

    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    CameraFormat videoFormat = CAMERA_FORMAT_YUV_420_SP;
    Size videoSize;
    videoSize.width = VIDEO_DEFAULT_WIDTH;
    videoSize.height = VIDEO_DEFAULT_HEIGHT;
    std::vector<int32_t> videoFramerates = {30, 30};
    VideoProfile profile = VideoProfile(videoFormat, videoSize, videoFramerates);
    sptr<VideoOutput> video = cameraManager_->CreateVideoOutput(profile, surface);
    ASSERT_NE(video, nullptr);

    sptr<CaptureOutput> output = video;
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    std::vector<VideoMetaType> supportedVideoMetaTypes = video->GetSupportedVideoMetaTypes();
    EXPECT_EQ(supportedVideoMetaTypes.size(), 0);

    EXPECT_EQ(input->Release(), 0);
    EXPECT_EQ(session->Release(), 0);
}

/*
 * Feature: Framework
 * Function: Test CameraServerDied in videoOutput
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CameraServerDied in videoOutput
 */
HWTEST_F(CameraVedioOutputUnit, video_output_unittest_006, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();
    ASSERT_FALSE(cameras.empty());
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }

    sptr<CaptureOutput> output = CreateVideoOutput();
    ASSERT_NE(output, nullptr);
    sptr<VideoOutput> videoOutput = (sptr<VideoOutput>&)output;

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(output), 0);
    EXPECT_EQ(session->CommitConfig(), 0);
    EXPECT_EQ(session->Start(), 0);

    pid_t pid = 0;
    videoOutput->CameraServerDied(pid);
    videoOutput->appCallback_ = nullptr;
    videoOutput->CameraServerDied(pid);

    EXPECT_EQ(input->Release(), 0);
    EXPECT_EQ(session->Release(), 0);
}

/*
 * Feature: Framework
 * Function: Test videooutput with cameraserverdied when stream_ is nullptr
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test videooutput with cameraserverdied when stream_ is nullptr
 */
HWTEST_F(CameraVedioOutputUnit, video_output_unittest_007, TestSize.Level1)
{
    int32_t width = VIDEO_DEFAULT_WIDTH;
    int32_t height = VIDEO_DEFAULT_HEIGHT;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    CameraFormat videoFormat = CAMERA_FORMAT_YUV_420_SP;
    Size videoSize;
    videoSize.width = width;
    videoSize.height = height;
    std::vector<int32_t> videoFramerates = {30, 30};
    VideoProfile videoProfile = VideoProfile(videoFormat, videoSize, videoFramerates);
    sptr<VideoOutput> video = cameraManager_->CreateVideoOutput(videoProfile, surface);
    ASSERT_NE(video, nullptr);

    pid_t pid = 0;
    video->stream_ = nullptr;
    std::shared_ptr<VideoStateCallback> setCallback =
        std::make_shared<TestVideoOutputCallback>("VideoStateCallback");
    video->SetCallback(setCallback);
    video->CameraServerDied(pid);
}

/*
 * Feature: Framework
 * Function: Test videooutput with OnSketchStatusChanged
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test videooutput with OnSketchStatusChanged
 */
HWTEST_F(CameraVedioOutputUnit, video_output_unittest_008, TestSize.Level1)
{
    int32_t width = VIDEO_DEFAULT_WIDTH;
    int32_t height = VIDEO_DEFAULT_HEIGHT;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    CameraFormat videoFormat = CAMERA_FORMAT_YUV_420_SP;
    Size videoSize;
    videoSize.width = width;
    videoSize.height = height;
    std::vector<int32_t> videoFramerates = {30, 30};
    VideoProfile videoProfile = VideoProfile(videoFormat, videoSize, videoFramerates);
    sptr<VideoOutput> video = cameraManager_->CreateVideoOutput(videoProfile, surface);
    ASSERT_NE(video, nullptr);

    std::shared_ptr<VideoOutputCallbackImpl> callback = std::make_shared<VideoOutputCallbackImpl>(video);
    SketchStatus status = SketchStatus::STOPPING;
    int32_t ret = callback->OnSketchStatusChanged(status);
    EXPECT_EQ(ret, CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test videooutput with enableMirror
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test videooutput with enableMirror
 */
HWTEST_F(CameraVedioOutputUnit, video_output_unittest_009, TestSize.Level1)
{
    int32_t width = VIDEO_DEFAULT_WIDTH;
    int32_t height = VIDEO_DEFAULT_HEIGHT;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    CameraFormat videoFormat = CAMERA_FORMAT_YUV_420_SP;
    Size videoSize;
    videoSize.width = width;
    videoSize.height = height;
    std::vector<int32_t> videoFramerates = {30, 30};
    VideoProfile videoProfile = VideoProfile(videoFormat, videoSize, videoFramerates);
    sptr<VideoOutput> video = cameraManager_->CreateVideoOutput(videoProfile, surface);
    ASSERT_NE(video, nullptr);

    video->session_ = nullptr;
    int32_t ret = video->enableMirror(true);
    EXPECT_EQ(ret, CameraErrorCode::SESSION_NOT_CONFIG);
}

/*
 * Feature: Framework
 * Function: Test videooutput with AutoDeferredVideoEnhancement
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test videooutput with AutoDeferredVideoEnhancement
 */
HWTEST_F(CameraVedioOutputUnit, video_output_unittest_010, TestSize.Level1)
{
    int32_t width = VIDEO_DEFAULT_WIDTH;
    int32_t height = VIDEO_DEFAULT_HEIGHT;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    CameraFormat videoFormat = CAMERA_FORMAT_YUV_420_SP;
    Size videoSize;
    videoSize.width = width;
    videoSize.height = height;
    std::vector<int32_t> videoFramerates = {30, 30};
    VideoProfile videoProfile = VideoProfile(videoFormat, videoSize, videoFramerates);
    sptr<VideoOutput> video = cameraManager_->CreateVideoOutput(videoProfile, surface);
    ASSERT_NE(video, nullptr);

    video->session_ = nullptr;
    int32_t ret = video->IsAutoDeferredVideoEnhancementSupported();
    EXPECT_EQ(ret, SERVICE_FATL_ERROR);

    ret = video->IsAutoDeferredVideoEnhancementEnabled();
    EXPECT_EQ(ret, SERVICE_FATL_ERROR);

    ret = video->EnableAutoDeferredVideoEnhancement(false);
    EXPECT_EQ(ret, SERVICE_FATL_ERROR);
}

/*
 * Feature: Framework
 * Function: Test videooutput with IsVideoStarted
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test videooutput with IsVideoStarted
 */
HWTEST_F(CameraVedioOutputUnit, video_output_unittest_011, TestSize.Level1)
{
    int32_t width = VIDEO_DEFAULT_WIDTH;
    int32_t height = VIDEO_DEFAULT_HEIGHT;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    CameraFormat videoFormat = CAMERA_FORMAT_YUV_420_SP;
    Size videoSize;
    videoSize.width = width;
    videoSize.height = height;
    std::vector<int32_t> videoFramerates = {30, 30};
    VideoProfile videoProfile = VideoProfile(videoFormat, videoSize, videoFramerates);
    sptr<VideoOutput> video = cameraManager_->CreateVideoOutput(videoProfile, surface);
    ASSERT_NE(video, nullptr);

    video->isVideoStarted_ = false;
    int32_t ret = video->IsVideoStarted();
    EXPECT_FALSE(ret);
}

/*
 * Feature: Framework
 * Function: Test videooutput with Rotation
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test videooutput with Rotation
 */
HWTEST_F(CameraVedioOutputUnit, video_output_unittest_012, TestSize.Level1)
{
    int32_t width = VIDEO_DEFAULT_WIDTH;
    int32_t height = VIDEO_DEFAULT_HEIGHT;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    CameraFormat videoFormat = CAMERA_FORMAT_YUV_420_SP;
    Size videoSize;
    videoSize.width = width;
    videoSize.height = height;
    std::vector<int32_t> videoFramerates = {30, 30};
    VideoProfile videoProfile = VideoProfile(videoFormat, videoSize, videoFramerates);
    sptr<VideoOutput> video = cameraManager_->CreateVideoOutput(videoProfile, surface);
    ASSERT_NE(video, nullptr);

    video->session_ = nullptr;
    std::vector<int32_t> rotations;
    rotations.push_back(0);
    int32_t ret = video->GetSupportedRotations(rotations);
    EXPECT_EQ(ret, SERVICE_FATL_ERROR);

    bool isSupported = false;
    ret = video->IsRotationSupported(isSupported);
    EXPECT_EQ(ret, SERVICE_FATL_ERROR);

    int32_t rotation = 0;
    ret = video->SetRotation(rotation);
    EXPECT_EQ(ret, SERVICE_FATL_ERROR);
}

/*
 * Feature: Framework
 * Function: Test videooutput with OnFramePaused
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test videooutput with OnFramePaused
 */
HWTEST_F(CameraVedioOutputUnit, video_output_unittest_013, TestSize.Level1)
{
    int32_t width = VIDEO_DEFAULT_WIDTH;
    int32_t height = VIDEO_DEFAULT_HEIGHT;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    CameraFormat videoFormat = CAMERA_FORMAT_YUV_420_SP;
    Size videoSize;
    videoSize.width = width;
    videoSize.height = height;
    std::vector<int32_t> videoFramerates = {30, 30};
    VideoProfile videoProfile = VideoProfile(videoFormat, videoSize, videoFramerates);
    sptr<VideoOutput> video = cameraManager_->CreateVideoOutput(videoProfile, surface);
    ASSERT_NE(video, nullptr);

    std::shared_ptr<VideoOutputCallbackImpl> callback = std::make_shared<VideoOutputCallbackImpl>(video);
    int32_t ret = callback->OnFramePaused();
    EXPECT_EQ(ret, CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test videooutput with OnFrameResumed
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test videooutput with OnFrameResumed
 */
HWTEST_F(CameraVedioOutputUnit, video_output_unittest_014, TestSize.Level1)
{
    int32_t width = VIDEO_DEFAULT_WIDTH;
    int32_t height = VIDEO_DEFAULT_HEIGHT;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    CameraFormat videoFormat = CAMERA_FORMAT_YUV_420_SP;
    Size videoSize;
    videoSize.width = width;
    videoSize.height = height;
    std::vector<int32_t> videoFramerates = {30, 30};
    VideoProfile videoProfile = VideoProfile(videoFormat, videoSize, videoFramerates);
    sptr<VideoOutput> video = cameraManager_->CreateVideoOutput(videoProfile, surface);
    ASSERT_NE(video, nullptr);

    std::shared_ptr<VideoOutputCallbackImpl> callback = std::make_shared<VideoOutputCallbackImpl>(video);
    int32_t ret = callback->OnFrameResumed();
    EXPECT_EQ(ret, CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test VideoOutput with IsAutoVideoFrameRateSupported, EnableAutoVideoFrameRate.
 * IsVideoDeferred
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test IsAutoVideoFrameRateSupported, EnableAutoVideoFrameRate for just call.
 */
HWTEST_F(CameraVedioOutputUnit, video_output_function_unittest_001, TestSize.Level1)
{
    int32_t width = VIDEO_DEFAULT_WIDTH;
    int32_t height = VIDEO_DEFAULT_HEIGHT;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    CameraFormat videoFormat = CAMERA_FORMAT_YUV_420_SP;
    Size videoSize;
    videoSize.width = width;
    videoSize.height = height;
    std::vector<int32_t> videoFramerates = {30, 30};
    VideoProfile videoProfile = VideoProfile(videoFormat, videoSize, videoFramerates);
    sptr<VideoOutput> video = cameraManager_->CreateVideoOutput(videoProfile, surface);
    ASSERT_NE(video, nullptr);
    video->session_ = nullptr;
    EXPECT_FALSE(video->IsAutoVideoFrameRateSupported());
    bool enable = false;
    EXPECT_EQ(video->EnableAutoVideoFrameRate(enable), CameraErrorCode::SESSION_NOT_CONFIG);
    int32_t minFrameRate = 0;
    int32_t maxFrameRate = 1;
    EXPECT_EQ(video->SetFrameRate(minFrameRate, maxFrameRate), CameraErrorCode::SESSION_NOT_CONFIG);
}

/*
 * Feature: Framework
 * Function: Test VideoOutputCallbackImpl with Constructor and Destructors.
 * IsVideoDeferred
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test Constructor and Destructors for just call.
 */
HWTEST_F(CameraVedioOutputUnit, video_output_function_unittest_002, TestSize.Level1)
{
    std::shared_ptr<VideoOutputCallbackImpl> videoOutputCallbackImpl1 = std::make_shared<VideoOutputCallbackImpl>();
    EXPECT_EQ(videoOutputCallbackImpl1->videoOutput_, nullptr);
    std::shared_ptr<VideoOutputCallbackImpl> videoOutputCallbackImpl2 =
        std::make_shared<VideoOutputCallbackImpl>(nullptr);
    EXPECT_EQ(videoOutputCallbackImpl2->videoOutput_, nullptr);
}

/*
 * Feature: Framework
 * Function: Test videooutput with OnFrameStarted
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test videooutput with OnFrameStarted
 */
HWTEST_F(CameraVedioOutputUnit, video_output_function_unittest_003, TestSize.Level0)
{
    int32_t width = VIDEO_DEFAULT_WIDTH;
    int32_t height = VIDEO_DEFAULT_HEIGHT;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    CameraFormat videoFormat = CAMERA_FORMAT_YUV_420_SP;
    Size videoSize;
    videoSize.width = width;
    videoSize.height = height;
    std::vector<int32_t> videoFramerates = {30, 30};
    VideoProfile videoProfile = VideoProfile(videoFormat, videoSize, videoFramerates);
    sptr<VideoOutput> video = cameraManager_->CreateVideoOutput(videoProfile, surface);
    ASSERT_NE(video, nullptr);

    std::shared_ptr<VideoOutputCallbackImpl> callback = std::make_shared<VideoOutputCallbackImpl>(video);
    std::shared_ptr<TestVideoOutputCallback> innerCallback =
        std::make_shared<TestVideoOutputCallback>("VideoStateCallback");
    innerCallback->OnFrameStarted();
}

/*
 * Feature: Framework
 * Function: Test videooutput with OnFrameEnded
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test videooutput with OnFrameEnded
 */
HWTEST_F(CameraVedioOutputUnit, video_output_function_unittest_004, TestSize.Level0)
{
    int32_t width = VIDEO_DEFAULT_WIDTH;
    int32_t height = VIDEO_DEFAULT_HEIGHT;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    CameraFormat videoFormat = CAMERA_FORMAT_YUV_420_SP;
    Size videoSize;
    videoSize.width = width;
    videoSize.height = height;
    std::vector<int32_t> videoFramerates = {30, 30};
    VideoProfile videoProfile = VideoProfile(videoFormat, videoSize, videoFramerates);
    sptr<VideoOutput> video = cameraManager_->CreateVideoOutput(videoProfile, surface);
    ASSERT_NE(video, nullptr);

    std::shared_ptr<VideoOutputCallbackImpl> callback = std::make_shared<VideoOutputCallbackImpl>(video);
    std::shared_ptr<TestVideoOutputCallback> innerCallback =
        std::make_shared<TestVideoOutputCallback>("VideoStateCallback");
    innerCallback->OnFrameEnded(0);
}

/*
 * Feature: Framework
 * Function: Test videooutput with OnError
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test videooutput with OnError
 */
HWTEST_F(CameraVedioOutputUnit, video_output_function_unittest_005, TestSize.Level0)
{
    int32_t width = VIDEO_DEFAULT_WIDTH;
    int32_t height = VIDEO_DEFAULT_HEIGHT;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    CameraFormat videoFormat = CAMERA_FORMAT_YUV_420_SP;
    Size videoSize;
    videoSize.width = width;
    videoSize.height = height;
    std::vector<int32_t> videoFramerates = {30, 30};
    VideoProfile videoProfile = VideoProfile(videoFormat, videoSize, videoFramerates);
    sptr<VideoOutput> video = cameraManager_->CreateVideoOutput(videoProfile, surface);
    ASSERT_NE(video, nullptr);

    std::shared_ptr<VideoOutputCallbackImpl> callback = std::make_shared<VideoOutputCallbackImpl>(video);
    std::shared_ptr<TestVideoOutputCallback> innerCallback =
        std::make_shared<TestVideoOutputCallback>("VideoStateCallback");
    innerCallback->OnError(CameraErrorCode::SERVICE_FATL_ERROR);
}

/*
 * Feature: Framework
 * Function: Test GetApplicationCallback
 * IsVideoDeferred
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetApplicationCallback()
 */
HWTEST_F(CameraVedioOutputUnit, video_output_function_unittest_003, TestSize.Level0)
{
    int32_t width = VIDEO_DEFAULT_WIDTH;
    int32_t height = VIDEO_DEFAULT_HEIGHT;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    CameraFormat videoFormat = CAMERA_FORMAT_YUV_420_SP;
    Size videoSize;
    videoSize.width = width;
    videoSize.height = height;
    std::vector<int32_t> videoFramerates = {30, 30};
    VideoProfile videoProfile = VideoProfile(videoFormat, videoSize, videoFramerates);
    sptr<VideoOutput> video = cameraManager_->CreateVideoOutput(videoProfile, surface);
    ASSERT_NE(video, nullptr);

    video->appCallback_ = nullptr;
    EXPECT_EQ(video->GetApplicationCallback(), nullptr);
    std::shared_ptr<VideoOutputCallbackImpl> videoOutputCallbackImpl1 = std::make_shared<VideoOutputCallbackImpl>();
    videoOutputCallbackImpl1->OnFrameStarted();
    videoOutputCallbackImpl1->OnFrameEnded(0);
    videoOutputCallbackImpl1->OnFrameError(0);
    CaptureEndedInfoExt info = {0, 0, true, "1"};
    videoOutputCallbackImpl1->OnDeferredVideoEnhancementInfo(info);
    EXPECT_EQ(videoOutputCallbackImpl1->videoOutput_, nullptr);
}
}
}
