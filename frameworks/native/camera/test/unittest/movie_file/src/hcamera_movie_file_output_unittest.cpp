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
#include "hcamera_movie_file_output_unittest.h"
#include "hcamera_movie_file_output.h"
#include "camera_util.h"
#include "camera/v1_5/types.h"
#include "camera_types.h"
#include "camera_log.h"
#include "hstream_repeat.h"
#include "hstream_common.h"
#include "imovie_file_output_callback.h"
#include "movie_file_common_const.h"
#include "movie_file_controller_video.h"
#include "movie_file_output_stub.h"
#include "sp_holder.h"
#include "avcodec_list.h"
#include "image_effect_filter.h"
#include "ipc_skeleton.h"
#include "token_setproc.h"
#include "test_common.h"
#include "test_token.h"
#include "gmock/gmock.h"
#include "surface_type.h"

using namespace testing::ext;
using namespace testing;
namespace OHOS {
namespace CameraStandard {
class MockMovieFileProxy : public MovieFileProxy {
public:
    MockMovieFileProxy():MovieFileProxy(nullptr, nullptr) {};
    MOCK_METHOD(int32_t, MuxMovieFileStart, (int64_t timestamp, MovieSettings movieSettings, int32_t cameraPosition), (override));
    MOCK_METHOD(void, MuxMovieFilePause, (int64_t timestamp), (override));
    MOCK_METHOD(void, MuxMovieFileResume, (), (override));
    MOCK_METHOD(std::string, MuxMovieFileStop, (int64_t timestamp), (override));
    MOCK_METHOD(bool, WaitFirstFrame, (), (override));
    MOCK_METHOD(void, ChangeCodecSettings, (VideoCodecType codecType, int32_t rotation, bool isBFrame, int32_t videoBitrate), (override));
    MOCK_METHOD(sptr<OHOS::IBufferProducer>, GetVideoProducer, (), (override));
    MOCK_METHOD(void, AddVideoFilter, (const std::string& filterName, const std::string& filterParam), (override));
    MOCK_METHOD(void, RemoveVideoFilter, (const std::string& filterName), (override));
    MOCK_METHOD(void, ReleaseConsumer, (), (override));
    ~MockMovieFileProxy() {}
};

class MockHStreamRepeat : public HStreamRepeat {
public:
    MockHStreamRepeat():HStreamRepeat(nullptr, 0, 0, 0, RepeatStreamType::VIDEO) {};
    MOCK_METHOD(int32_t, Start, (), (override));
    MOCK_METHOD(int32_t, Stop, (), (override));
    MOCK_METHOD(int32_t, SetCallback, (const sptr<IStreamRepeatCallback>& callback), (override));
    MOCK_METHOD(int32_t, AddDeferredSurface, (const sptr<OHOS::IBufferProducer>& producer), (override));
    MOCK_METHOD(int32_t, Release, (), (override));
    ~MockHStreamRepeat() {}
};

void HcameraMovieFileOutputUnittest::SetUpTestCase(void) {
    MEDIA_INFO_LOG("HcameraMovieFileOutputUnittest::SetUpTestCase");
}

void HcameraMovieFileOutputUnittest::TearDownTestCase(void) {
    MEDIA_INFO_LOG("HcameraMovieFileOutputUnittest::TearDownTestCase");
}

void HcameraMovieFileOutputUnittest::SetUp() {
    MEDIA_INFO_LOG("HcameraMovieFileOutputUnittest::SetUpsetup begin");
    int32_t format = 0;
    int32_t width = 1920;
    int32_t height = 1080;
    HCameraMovieFileOutput::MovieFileOutputFrameRateRange frameRateRange = {30, 60};
    this->hcameraMovieFileOutputTest =
        std::make_unique<HCameraMovieFileOutput>(format, width, height, frameRateRange);

}

void HcameraMovieFileOutputUnittest::TearDown() {
    MEDIA_INFO_LOG("TearDown begin");
    if(hcameraMovieFileOutputTest != nullptr) {
        hcameraMovieFileOutputTest->Release();
    }
}



/*
 * Feature: HcameraMovieFileOutput
 * Function: Test HCameraMovieFileOutput constructor.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test HCameraMovieFileOutput constructor to check if the appuid apppid appTokenId_ appFullTokenId_ bundleName_ are not null.
 */
HWTEST_F(HcameraMovieFileOutputUnittest, hcamera_movie_file_output_unittest_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("hcamera_movie_file_output_unittest_001 begin");
    EXPECT_EQ(hcameraMovieFileOutputTest->appUid_, 0);
    EXPECT_NE(hcameraMovieFileOutputTest->appPid_, 0);
    EXPECT_NE(hcameraMovieFileOutputTest->appTokenId_, 0);
    EXPECT_NE(hcameraMovieFileOutputTest->appFullTokenId_, 0);
    MEDIA_INFO_LOG("hcamera_movie_file_output_unittest_001 end");
}

/*
 * Feature: HcameraMovieFileOutput
 * Function: Test HCameraMovieFileOutput::InitConfig.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test HCameraMovieFileOutput initconfig result when input invalid opMode.
 */
HWTEST_F(HcameraMovieFileOutputUnittest, hcamera_movie_file_output_unittest_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("hcamera_movie_file_output_unittest_002 begin");
    int32_t opMode = -1;
    int32_t result = hcameraMovieFileOutputTest->InitConfig(opMode);
    EXPECT_EQ(result, CamServiceError::CAMERA_UNKNOWN_ERROR);
    EXPECT_EQ(hcameraMovieFileOutputTest->videoStreamRepeat_.Get(), nullptr);
    MEDIA_INFO_LOG("hcamera_movie_file_output_unittest_002 end");
}

/*
 * Feature: HcameraMovieFileOutput
 * Function: Test HCameraMovieFileOutput::InitConfig.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test HCameraMovieFileOutput initconfig result when input HDI::Camera::V1_5::OperationMode::VIDEO.
 */
HWTEST_F(HcameraMovieFileOutputUnittest, hcamera_movie_file_output_unittest_003, TestSize.Level0)
{
    MEDIA_INFO_LOG("hcamera_movie_file_output_unittest_003 begin");
    int32_t opMode = HDI::Camera::V1_5::OperationMode::VIDEO;
    int32_t result = hcameraMovieFileOutputTest->InitConfig(opMode);
    EXPECT_EQ(result, CamServiceError::CAMERA_OK);
    EXPECT_NE(hcameraMovieFileOutputTest->movieFileProxy_.Get(), nullptr);
    EXPECT_NE(hcameraMovieFileOutputTest->videoStreamRepeat_.Get(), nullptr);
    sptr<HStreamRepeat> videoStreamRepeat = hcameraMovieFileOutputTest->videoStreamRepeat_.Get();
    std::vector<int32_t> frameRate = videoStreamRepeat->GetFrameRateRange();
    EXPECT_EQ(frameRate[0], hcameraMovieFileOutputTest->frameRateRange_.minFrameRate);
    EXPECT_EQ(frameRate[1], hcameraMovieFileOutputTest->frameRateRange_.maxFrameRate);
    MEDIA_INFO_LOG("hcamera_movie_file_output_unittest_003 end");
}

/*
 * Feature: HcameraMovieFileOutput
 * Function: Test HCameraMovieFileOutput::Start.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test HCameraMovieFileOutput::Start function when all dependencies are valid.
 */
HWTEST_F(HcameraMovieFileOutputUnittest, hcamera_movie_file_output_unittest_004, TestSize.Level0)
{
    MEDIA_INFO_LOG("hcamera_movie_file_output_unittest_004 begin");
    auto mockMovieFileProxy = std::make_shared<MockMovieFileProxy>();
    sptr<MockHStreamRepeat> mockVideoStreamRepeat = new MockHStreamRepeat();
    EXPECT_CALL(*mockMovieFileProxy, MuxMovieFileStart(_, _, _)).WillOnce(Return(CamServiceError::CAMERA_OK));
    EXPECT_CALL(*mockVideoStreamRepeat, SetCallback(_)).WillOnce(Return(CamServiceError::CAMERA_OK));
    EXPECT_CALL(*mockVideoStreamRepeat, Start()).WillOnce(Return(CamServiceError::CAMERA_OK));

    hcameraMovieFileOutputTest->movieFileProxy_.Set(mockMovieFileProxy);
    hcameraMovieFileOutputTest->videoStreamRepeat_.Set(mockVideoStreamRepeat);
    hcameraMovieFileOutputTest->SetMovieFileOutputCallback(nullptr);
    int32_t result = hcameraMovieFileOutputTest->Start();
    EXPECT_EQ(result, CamServiceError::CAMERA_OK);
    MEDIA_INFO_LOG("hcamera_movie_file_output_unittest_004 end");
}

/*
 * Feature: HcameraMovieFileOutput
 * Function: Test HCameraMovieFileOutput::Stop.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test HCameraMovieFileOutput::Stop function when all dependencies are valid.
 */
HWTEST_F(HcameraMovieFileOutputUnittest, hcamera_movie_file_output_unittest_005, TestSize.Level0)
{
    MEDIA_INFO_LOG("hcamera_movie_file_output_unittest_005 begin");
    auto mockMovieFileProxy = std::make_shared<MockMovieFileProxy>();
    sptr<MockHStreamRepeat> mockVideoStreamRepeat = new MockHStreamRepeat();
    EXPECT_CALL(*mockMovieFileProxy, WaitFirstFrame()).WillOnce(Return(true));
    EXPECT_CALL(*mockVideoStreamRepeat, Stop()).WillOnce(Return(CamServiceError::CAMERA_OK));
    EXPECT_CALL(*mockMovieFileProxy, MuxMovieFileStop(_)).WillOnce(Return("file:///path/to/movie.mp4"));
    hcameraMovieFileOutputTest->movieFileProxy_.Set(mockMovieFileProxy);
    hcameraMovieFileOutputTest->videoStreamRepeat_.Set(mockVideoStreamRepeat);
    hcameraMovieFileOutputTest->SetMovieFileOutputCallback(nullptr);
    int32_t result = hcameraMovieFileOutputTest->Stop();
    EXPECT_EQ(result, CamServiceError::CAMERA_OK);
    MEDIA_INFO_LOG("hcamera_movie_file_output_unittest_005 end");
}

/*
 * Feature: HcameraMovieFileOutput
 * Function: Test HCameraMovieFileOutput::Pause.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test HCameraMovieFileOutput::Pause function when all dependencies are valid.
 */
HWTEST_F(HcameraMovieFileOutputUnittest, hcamera_movie_file_output_unittest_006, TestSize.Level0)
{
    MEDIA_INFO_LOG("hcamera_movie_file_output_unittest_006 begin");
    auto mockMovieFileProxy = std::make_shared<MockMovieFileProxy>();
    sptr<MockHStreamRepeat> mockVideoStreamRepeat = new MockHStreamRepeat();

    EXPECT_CALL(*mockMovieFileProxy, WaitFirstFrame()).WillOnce(Return(true));
    EXPECT_CALL(*mockVideoStreamRepeat, Stop()).WillOnce(Return(CamServiceError::CAMERA_OK));
    EXPECT_CALL(*mockMovieFileProxy, MuxMovieFilePause(_)).WillOnce(Return());
    hcameraMovieFileOutputTest->SetMovieFileOutputCallback(nullptr);
    hcameraMovieFileOutputTest->movieFileProxy_.Set(mockMovieFileProxy);
    hcameraMovieFileOutputTest->videoStreamRepeat_.Set(mockVideoStreamRepeat);
    int32_t result = hcameraMovieFileOutputTest->Pause();
    EXPECT_EQ(result, CamServiceError::CAMERA_OK);
    MEDIA_INFO_LOG("hcamera_movie_file_output_unittest_006 end");
}

/*
 * Feature: HcameraMovieFileOutput
 * Function: Test HCameraMovieFileOutput::Resume.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test HCameraMovieFileOutput::Resume function when all dependencies are valid.
 */
HWTEST_F(HcameraMovieFileOutputUnittest, hcamera_movie_file_output_unittest_007, TestSize.Level0)
{
    MEDIA_INFO_LOG("hcamera_movie_file_output_unittest_007 begin");
    auto mockMovieFileProxy = std::make_shared<MockMovieFileProxy>();
    sptr<MockHStreamRepeat> mockVideoStreamRepeat = new MockHStreamRepeat();
    EXPECT_CALL(*mockMovieFileProxy, MuxMovieFileResume()).WillOnce(Return());
    EXPECT_CALL(*mockVideoStreamRepeat, Start()).WillOnce(Return(CamServiceError::CAMERA_OK));
    hcameraMovieFileOutputTest->SetMovieFileOutputCallback(nullptr);
    hcameraMovieFileOutputTest->movieFileProxy_.Set(mockMovieFileProxy);
    hcameraMovieFileOutputTest->videoStreamRepeat_.Set(mockVideoStreamRepeat);
    int32_t result = hcameraMovieFileOutputTest->Resume();
    EXPECT_EQ(result, CamServiceError::CAMERA_OK);
    MEDIA_INFO_LOG("hcamera_movie_file_output_unittest_007 end");
}

/*
 * Feature: HcameraMovieFileOutput
 * Function: Test HCameraMovieFileOutput::SetOutputSettings.
 * SubFunction: NA
 * FunctionPoints: Test SetOutputSettings with valid parameters and verify the expected behavior.
 * EnvConditions: NA
 * CaseDescription: Test HCameraMovieFileOutput::SetOutputSettings function when all dependencies are valid.
 */
HWTEST_F(HcameraMovieFileOutputUnittest, hcamera_movie_file_output_unittest_008, TestSize.Level0)
{
    MEDIA_INFO_LOG("hcamera_movie_file_output_unittest_008 begin");
    auto mockMovieFileProxy = std::make_shared<MockMovieFileProxy>();
    sptr<MockHStreamRepeat> mockVideoStreamRepeat = new MockHStreamRepeat();
    EXPECT_CALL(*mockMovieFileProxy, ChangeCodecSettings(_, _, _, _)).WillOnce(Return());
    EXPECT_CALL(*mockMovieFileProxy, GetVideoProducer()).WillOnce(Return(nullptr));
    EXPECT_CALL(*mockVideoStreamRepeat, AddDeferredSurface(_)).WillOnce(Return(CamServiceError::CAMERA_OK));
    MovieSettings testSettings;
    testSettings.videoCodecType = VideoCodecType::VIDEO_ENCODE_TYPE_AVC;
    testSettings.rotation = 90;
    testSettings.isBFrameEnabled = true;
    hcameraMovieFileOutputTest->movieFileProxy_.Set(mockMovieFileProxy);
    hcameraMovieFileOutputTest->videoStreamRepeat_.Set(mockVideoStreamRepeat);
    int32_t result = hcameraMovieFileOutputTest->SetOutputSettings(testSettings);
    EXPECT_EQ(result, CamServiceError::CAMERA_OK);
    MEDIA_INFO_LOG("hcamera_movie_file_output_unittest_008 end");
}

/*
 * Feature: HcameraMovieFileOutput
 * Function: Test HCameraMovieFileOutput::GetSupportedVideoFilters.
 * SubFunction: NA
 * FunctionPoints: Test GetSupportedVideoFilters with valid parameters and verify the expected behavior.
 * EnvConditions: NA
 * CaseDescription: Test HCameraMovieFileOutput::GetSupportedVideoFilters function when all dependencies are valid.
 */
HWTEST_F(HcameraMovieFileOutputUnittest, hcamera_movie_file_output_unittest_009, TestSize.Level0)
{
    MEDIA_INFO_LOG("hcamera_movie_file_output_unittest_009 begin");
    std::vector<std::string> supportedVideoFilters;
    int32_t result = hcameraMovieFileOutputTest->GetSupportedVideoFilters(supportedVideoFilters);
    EXPECT_EQ(result, CamServiceError::CAMERA_OK);
    MEDIA_INFO_LOG("hcamera_movie_file_output_unittest_009 end");
}

/*
 * Feature: HcameraMovieFileOutput
 * Function: Test HCameraMovieFileOutput::SetMovieFileOutputCallback.
 * SubFunction: NA
 * FunctionPoints: Test SetMovieFileOutputCallback with valid parameters and verify the expected behavior.
 * EnvConditions: NA
 * CaseDescription: Test HCameraMovieFileOutput::SetMovieFileOutputCallback function when all dependencies are valid.
 */
HWTEST_F(HcameraMovieFileOutputUnittest, hcamera_movie_file_output_unittest_010, TestSize.Level0)
{
    MEDIA_INFO_LOG("hcamera_movie_file_output_unittest_010 begin");
    sptr<IMovieFileOutputCallback> mockCallback = nullptr;
    int32_t result = hcameraMovieFileOutputTest->SetMovieFileOutputCallback(mockCallback);
    EXPECT_EQ(result, CamServiceError::CAMERA_OK);
    MEDIA_INFO_LOG("hcamera_movie_file_output_unittest_010 end");
}

/*
 * Feature: HcameraMovieFileOutput
 * Function: Test HCameraMovieFileOutput::UnsetMovieFileOutputCallback.
 * SubFunction: NA
 * FunctionPoints: Test UnsetMovieFileOutputCallback with valid parameters and verify the expected behavior.
 * EnvConditions: NA
 * CaseDescription: Test HCameraMovieFileOutput::UnsetMovieFileOutputCallback function when all dependencies are valid.
 */
HWTEST_F(HcameraMovieFileOutputUnittest, hcamera_movie_file_output_unittest_011, TestSize.Level0)
{
    MEDIA_INFO_LOG("hcamera_movie_file_output_unittest_011 begin");
    int32_t result = hcameraMovieFileOutputTest->UnsetMovieFileOutputCallback();
    EXPECT_EQ(result, CamServiceError::CAMERA_OK);
    EXPECT_EQ(hcameraMovieFileOutputTest->movieFileOutputCallback_, nullptr);
    MEDIA_INFO_LOG("hcamera_movie_file_output_unittest_011 end");
}

/*
 * Feature: HcameraMovieFileOutput
 * Function: Test HCameraMovieFileOutput::AddVideoFilter.
 * SubFunction: NA
 * FunctionPoints: Test AddVideoFilter with valid parameters and verify the expected behavior.
 * EnvConditions: NA
 * CaseDescription: Test HCameraMovieFileOutput::AddVideoFilter function when all dependencies are valid.
 */
HWTEST_F(HcameraMovieFileOutputUnittest, hcamera_movie_file_output_unittest_012, TestSize.Level0)
{
    MEDIA_INFO_LOG("hcamera_movie_file_output_unittest_012 begin");
    auto mockMovieFileProxy = std::make_shared<MockMovieFileProxy>();
    EXPECT_CALL(*mockMovieFileProxy, AddVideoFilter("testFilter", "testParam")).WillOnce(Return());
    hcameraMovieFileOutputTest->movieFileProxy_.Set(mockMovieFileProxy);
    int32_t result = hcameraMovieFileOutputTest->AddVideoFilter("testFilter", "testParam");
    EXPECT_EQ(result, CamServiceError::CAMERA_OK);
    MEDIA_INFO_LOG("hcamera_movie_file_output_unittest_012 end");
}

/*
 * Feature: HcameraMovieFileOutput
 * Function: Test HCameraMovieFileOutput::RemoveVideoFilter.
 * SubFunction: NA
 * FunctionPoints: Test RemoveVideoFilter with valid parameters and verify the expected behavior.
 * EnvConditions: NA
 * CaseDescription: Test HCameraMovieFileOutput::RemoveVideoFilter function when all dependencies are valid.
 */
HWTEST_F(HcameraMovieFileOutputUnittest, hcamera_movie_file_output_unittest_013, TestSize.Level0)
{
    MEDIA_INFO_LOG("hcamera_movie_file_output_unittest_013 begin");
    auto mockMovieFileProxy = std::make_shared<MockMovieFileProxy>();
    EXPECT_CALL(*mockMovieFileProxy, RemoveVideoFilter("testFilter")).WillOnce(Return());
    hcameraMovieFileOutputTest->movieFileProxy_.Set(mockMovieFileProxy);
    int32_t result = hcameraMovieFileOutputTest->RemoveVideoFilter("testFilter");
    EXPECT_EQ(result, CamServiceError::CAMERA_OK);
    MEDIA_INFO_LOG("hcamera_movie_file_output_unittest_013 end");
}


/*
 * Feature: HcameraMovieFileOutput
 * Function: Test HCameraMovieFileOutput::EnableMirror.
 * SubFunction: NA
 * FunctionPoints: Test EnableMirror with valid parameters and verify the expected behavior.
 * EnvConditions: NA
 * CaseDescription: Test HCameraMovieFileOutput::EnableMirror function when all dependencies are valid.
 */
HWTEST_F(HcameraMovieFileOutputUnittest, hcamera_movie_file_output_unittest_014, TestSize.Level0)
{
    MEDIA_INFO_LOG("hcamera_movie_file_output_unittest_014 begin");
    sptr<MockHStreamRepeat> mockVideoStreamRepeat = new MockHStreamRepeat();
    hcameraMovieFileOutputTest->videoStreamRepeat_.Set(mockVideoStreamRepeat);
    int32_t result = hcameraMovieFileOutputTest->EnableMirror(true);
    EXPECT_EQ(result, CamServiceError::CAMERA_OK);
    MEDIA_INFO_LOG("hcamera_movie_file_output_unittest_014 end");
}

/*
 * Feature: HcameraMovieFileOutput
 * Function: Test HCameraMovieFileOutput::IsMirrorEnabled.
 * SubFunction: NA
 * FunctionPoints: Test IsMirrorEnabled with valid parameters and verify the expected behavior.
 * EnvConditions: NA
 * CaseDescription: Test HCameraMovieFileOutput::IsMirrorEnabled function when all dependencies are valid.
 */
HWTEST_F(HcameraMovieFileOutputUnittest, hcamera_movie_file_output_unittest_015, TestSize.Level0)
{
    MEDIA_INFO_LOG("hcamera_movie_file_output_unittest_015 begin");
    auto mockMovieFileProxy = std::make_shared<MockMovieFileProxy>();
    sptr<MockHStreamRepeat> mockVideoStreamRepeat = new MockHStreamRepeat();
    bool isEnable = false;
    hcameraMovieFileOutputTest->videoStreamRepeat_.Set(mockVideoStreamRepeat);
    hcameraMovieFileOutputTest->EnableMirror(true);
    int32_t result = hcameraMovieFileOutputTest->IsMirrorEnabled(isEnable);
    EXPECT_EQ(isEnable, true);
    EXPECT_EQ(result, CamServiceError::CAMERA_OK);
    MEDIA_INFO_LOG("hcamera_movie_file_output_unittest_015 end");
}

/*
 * Feature: HcameraMovieFileOutput
 * Function: Test HCameraMovieFileOutput::Release.
 * SubFunction: NA
 * FunctionPoints: Test Release with valid parameters and verify the expected behavior.
 * EnvConditions: NA
 * CaseDescription: Test HCameraMovieFileOutput::Release function when all dependencies are valid.
 */
HWTEST_F(HcameraMovieFileOutputUnittest, hcamera_movie_file_output_unittest_016, TestSize.Level0)
{
    MEDIA_INFO_LOG("hcamera_movie_file_output_unittest_016 begin");
    auto mockMovieFileProxy = std::make_shared<MockMovieFileProxy>();
    sptr<MockHStreamRepeat> mockVideoStreamRepeat = new MockHStreamRepeat();
    EXPECT_CALL(*mockMovieFileProxy, ReleaseConsumer()).WillRepeatedly(Return());
    EXPECT_CALL(*mockVideoStreamRepeat, Release()).WillOnce(Return(CamServiceError::CAMERA_OK));
    hcameraMovieFileOutputTest->videoStreamRepeat_.Set(mockVideoStreamRepeat);
    hcameraMovieFileOutputTest->movieFileProxy_.Set(mockMovieFileProxy);
    int32_t result = hcameraMovieFileOutputTest->Release();
    EXPECT_EQ(hcameraMovieFileOutputTest->videoStreamRepeat_.Get(), nullptr);
    EXPECT_NE(hcameraMovieFileOutputTest->movieFileProxy_.Get(), nullptr);
    EXPECT_EQ(result, CamServiceError::CAMERA_OK);
    MEDIA_INFO_LOG("hcamera_movie_file_output_unittest_016 end");
}

/*
 * Feature: HCameraMovieFileOutput
 * Function: Test HCameraMovieFileOutput::OperatePermissionCheck.
 * SubFunction: NA
 * FunctionPoints: Test OperatePermissionCheck with valid and invalid parameters and verify the expected behavior.
 * EnvConditions: NA
 * CaseDescription: Test HCameraMovieFileOutput::OperatePermissionCheck function with different scenarios.
 */
HWTEST_F(HcameraMovieFileOutputUnittest, hcamera_movie_file_output_unittest_017, TestSize.Level0) {
    MEDIA_INFO_LOG("hcamera_movie_file_output_unittest_017 begin");
    hcameraMovieFileOutputTest->appTokenId_ = 5678;
    int32_t result2 = hcameraMovieFileOutputTest->OperatePermissionCheck(
        static_cast<uint32_t>(IMovieFileOutputIpcCode::COMMAND_START));
    EXPECT_EQ(result2, CamServiceError::CAMERA_OPERATION_NOT_ALLOWED);
    uint32_t invalidInterfaceCode = 0xffff;
    int32_t result3 = hcameraMovieFileOutputTest->OperatePermissionCheck(invalidInterfaceCode);
    EXPECT_EQ(result3, CamServiceError::CAMERA_OK);
    MEDIA_INFO_LOG("hcamera_movie_file_output_unittest_017 end");
}

/*
 * Feature: HCameraMovieFileOutput
 * Function: Test HCameraMovieFileOutput::GetStreams.
 * SubFunction: NA
 * FunctionPoints: Test GetStreams with valid parameters and verify the expected behavior.
 * EnvConditions: NA
 * CaseDescription: Test HCameraMovieFileOutput::GetStreams function when videoStreamRepeat_ is valid.
 */
HWTEST_F(HcameraMovieFileOutputUnittest, hcamera_movie_file_output_unittest_018, TestSize.Level0) {
    MEDIA_INFO_LOG("hcamera_movie_file_output_unittest_018 begin");
    std::vector<sptr<HStreamRepeat>> streams = hcameraMovieFileOutputTest->GetStreams();
    EXPECT_EQ(streams.size(), 1);
    EXPECT_EQ(streams[0], nullptr);
    int32_t opMode = HDI::Camera::V1_5::OperationMode::VIDEO;
    hcameraMovieFileOutputTest->InitConfig(opMode);
    std::vector<sptr<HStreamRepeat>> streams2 = hcameraMovieFileOutputTest->GetStreams();
    EXPECT_EQ(streams2.size(), 1);
    EXPECT_NE(streams2[0], nullptr);
    EXPECT_EQ(streams2[0], hcameraMovieFileOutputTest->videoStreamRepeat_.Get());
    MEDIA_INFO_LOG("hcamera_movie_file_output_unittest_018 end");
}

/*
 * Feature: HCameraMovieFileOutput
 * Function: Test HCameraMovieFileOutput::SetCameraPosition.
 * SubFunction: NA
 * FunctionPoints: Test SetCameraPosition with valid parameters and verify the expected behavior.
 * EnvConditions: NA
 * CaseDescription: Test HCameraMovieFileOutput::SetCameraPosition function when input position.
 */
HWTEST_F(HcameraMovieFileOutputUnittest, hcamera_movie_file_output_unittest_019, TestSize.Level0) {
    MEDIA_INFO_LOG("hcamera_movie_file_output_unittest_019 begin");
    int position = -1;
    hcameraMovieFileOutputTest->SetCameraPosition(position);
    EXPECT_EQ(position, hcameraMovieFileOutputTest->cameraPosition_);
    MEDIA_INFO_LOG("hcamera_movie_file_output_unittest_019 end");
}

}
}