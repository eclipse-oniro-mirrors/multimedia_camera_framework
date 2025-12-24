/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include "capture_session_dfx_utils_unittest.h"
#include "gtest/gtest.h"
#include "camera_log.h"
#include "test_token.h"

using namespace testing::ext;
using namespace testing;
namespace OHOS {
namespace CameraStandard {
void CaptureSessionDfxUtilsUnitTest::SetUpTestCase(void) {
    ASSERT_TRUE(TestToken().GetAllCameraPermission());
}

void CaptureSessionDfxUtilsUnitTest::TearDownTestCase(void) {}

void CaptureSessionDfxUtilsUnitTest::SetUp() {
    cameraManager_ = CameraManager::GetInstance();
    ASSERT_NE(cameraManager_, nullptr);
    cameras_ = cameraManager_->GetCameraDeviceListFromServer();
    ASSERT_FALSE(cameras_.empty());
}

void CaptureSessionDfxUtilsUnitTest::TearDown() {
}

void CaptureSessionDfxUtilsUnitTest::DisMdmOpenCheck(sptr<CameraInput> input)
{
    auto device = input->GetCameraDevice();
    ASSERT_NE(device, nullptr);
    device->SetMdmCheck(false);
}

void CaptureSessionDfxUtilsUnitTest::UpdateCameraOutputCapability(int32_t modeName)
{
    if (!cameraManager_ || cameras_.empty()) {
        return;
    }
    auto outputCapability = cameraManager_->GetSupportedOutputCapability(cameras_[0], modeName);
    ASSERT_NE(outputCapability, nullptr);

    previewProfile_ = outputCapability->GetPreviewProfiles();
    ASSERT_FALSE(previewProfile_.empty());

    photoProfile_ = outputCapability->GetPhotoProfiles();
    ASSERT_FALSE(photoProfile_.empty());

    videoProfile_ = outputCapability->GetVideoProfiles();
    ASSERT_FALSE(videoProfile_.empty());
}

/*
 * Feature: Framework
 * Function: Test CaptureSession::CameraDfxReportHelper with ExtractStreamConfigInfo
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test ExtractStreamConfigInfo after one preview output add.
 */
HWTEST_F(CaptureSessionDfxUtilsUnitTest, capture_session_dfx_utils_unittest_001, TestSize.Level0)
{
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    EXPECT_NE(session->cameraDfxReportHelper_, nullptr);
    sptr<CameraInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);
    DisMdmOpenCheck(input);
    sptr<CaptureInput> captureInput = input;
    captureInput->Open();

    UpdateCameraOutputCapability();
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(surface, nullptr);
    sptr<CaptureOutput> preview = cameraManager_->CreatePreviewOutput(previewProfile_[0], surface);
    ASSERT_NE(preview, nullptr);

    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(captureInput), 0);
    EXPECT_EQ(session->AddOutput(preview), 0);
    EXPECT_EQ(session->CommitConfig(), 0);
    
    std::vector<StreamConfigInfo> streamConfigInfos = session->cameraDfxReportHelper_->ExtractStreamConfigInfo();
    EXPECT_EQ(streamConfigInfos.size(), 1);
    EXPECT_EQ(streamConfigInfos[0].size.height, previewProfile_[0].GetSize().height);
    EXPECT_EQ(streamConfigInfos[0].size.width, previewProfile_[0].GetSize().width);
    EXPECT_EQ(streamConfigInfos[0].outputType, CaptureOutputType::CAPTURE_OUTPUT_TYPE_PREVIEW);
    EXPECT_EQ(streamConfigInfos[0].format, previewProfile_[0].GetCameraFormat());

    input->Close();
    preview->Release();
    input->Release();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test CaptureSession::CameraDfxReportHelper with ExtractModeConfigInfo
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test ExtractModeConfigInfo on video mode.
 */
HWTEST_F(CaptureSessionDfxUtilsUnitTest, capture_session_dfx_utils_unittest_002, TestSize.Level0)
{
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession(SceneMode::VIDEO);
    ASSERT_NE(session, nullptr);
    EXPECT_NE(session->cameraDfxReportHelper_, nullptr);
    sptr<CameraInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);
    DisMdmOpenCheck(input);
    sptr<CaptureInput> captureInput = input;
    captureInput->Open();

    UpdateCameraOutputCapability(SceneMode::VIDEO);
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(surface, nullptr);
    sptr<CaptureOutput> preview = cameraManager_->CreatePreviewOutput(previewProfile_[0], surface);
    ASSERT_NE(preview, nullptr);

    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(captureInput), 0);
    EXPECT_EQ(session->AddOutput(preview), 0);
    EXPECT_EQ(session->CommitConfig(), 0);

    ModeConfigInfo modeConfigInfo = session->cameraDfxReportHelper_->ExtractModeConfigInfo();
    EXPECT_EQ(modeConfigInfo.mode, SceneMode::VIDEO);

    input->Close();
    preview->Release();
    input->Release();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test CaptureSession::CameraDfxReportHelper with GetStreamTypeName
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetStreamTypeName with normal branch and abnormal branch.
 */
HWTEST_F(CaptureSessionDfxUtilsUnitTest, capture_session_dfx_utils_unittest_003, TestSize.Level0)
{
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    EXPECT_NE(session->cameraDfxReportHelper_, nullptr);
    std::string repeatStream = session->cameraDfxReportHelper_->GetStreamTypeName(StreamType::REPEAT);
    std::string STREAM_TYPE_REPEAT = "RepeatStream";
    EXPECT_EQ(repeatStream, STREAM_TYPE_REPEAT);

    std::string unknownStream = session->cameraDfxReportHelper_->GetStreamTypeName(static_cast<StreamType>(10));
    std::string STREAM_TYPE_UNKNOWN = "UnknownStream";
    EXPECT_EQ(unknownStream, STREAM_TYPE_UNKNOWN);
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test CaptureSession::CameraDfxReportHelper with GetRepeatStreamTypeName
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetRepeatStreamTypeName with normal branch and abnormal branch.
 */
HWTEST_F(CaptureSessionDfxUtilsUnitTest, capture_session_dfx_utils_unittest_004, TestSize.Level0)
{
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    EXPECT_NE(session->cameraDfxReportHelper_, nullptr);
    std::string moviefileOutput =
        session->cameraDfxReportHelper_->GetRepeatStreamTypeName(CaptureOutputType::CAPTURE_OUTPUT_TYPE_MOVIE_FILE);
    const std::string REPEAT_STREAM_TYPE_MOVIE_FILE = "MovieFile";
    EXPECT_EQ(moviefileOutput, REPEAT_STREAM_TYPE_MOVIE_FILE);

    std::string unknownOutput =
        session->cameraDfxReportHelper_->GetRepeatStreamTypeName(static_cast<CaptureOutputType>(10));
    const std::string REPEAT_STREAM_TYPE_UNKNOWN = "Unknown";
    EXPECT_EQ(unknownOutput, REPEAT_STREAM_TYPE_UNKNOWN);
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test CaptureSession::CameraDfxReportHelper with GetTypeName
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetTypeName when stream type is repeat and capture.
 */
HWTEST_F(CaptureSessionDfxUtilsUnitTest, capture_session_dfx_utils_unittest_005, TestSize.Level0)
{
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    EXPECT_NE(session->cameraDfxReportHelper_, nullptr);
    std::string videoType =
        session->cameraDfxReportHelper_->GetTypeName(StreamType::REPEAT, CaptureOutputType::CAPTURE_OUTPUT_TYPE_VIDEO);
    const std::string REPEAT_STREAM_TYPE_VIDEO = "RepeatStream:Video";
    EXPECT_EQ(videoType, REPEAT_STREAM_TYPE_VIDEO);

    std::string captureType = session->cameraDfxReportHelper_->GetTypeName(StreamType::CAPTURE,
        CaptureOutputType::CAPTURE_OUTPUT_TYPE_PREVIEW);
    const std::string CAPTURE_STREAM_TYPE = "CaptureStream";
    EXPECT_EQ(captureType, CAPTURE_STREAM_TYPE);
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test CaptureSession::CameraDfxReportHelper with ReportCameraConfigInfo
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test ReportCameraConfigInfo.
 */
HWTEST_F(CaptureSessionDfxUtilsUnitTest, capture_session_dfx_utils_unittest_006, TestSize.Level0)
{
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession(SceneMode::VIDEO);
    ASSERT_NE(session, nullptr);
    sptr<CameraInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);
    DisMdmOpenCheck(input);
    sptr<CaptureInput> captureInput = input;
    captureInput->Open();

    UpdateCameraOutputCapability(SceneMode::VIDEO);
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(surface, nullptr);
    sptr<CaptureOutput> preview = cameraManager_->CreatePreviewOutput(previewProfile_[0], surface);
    ASSERT_NE(preview, nullptr);

    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(captureInput), 0);
    EXPECT_EQ(session->AddOutput(preview), 0);
    EXPECT_EQ(session->CommitConfig(), 0);

    EXPECT_NE(session->cameraDfxReportHelper_, nullptr);
    session->cameraDfxReportHelper_->ReportCameraConfigInfo(0);

    input->Close();
    preview->Release();
    input->Release();
    session->Release();
}
}
}