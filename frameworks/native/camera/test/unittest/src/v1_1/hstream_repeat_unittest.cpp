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

#include "camera_log.h"
#include "hstream_repeat_unittest.h"
#include "camera_util.h"
#include "test_common.h"
#include "camera_service_ipc_interface_code.h"

using namespace testing::ext;
namespace OHOS {
namespace CameraStandard {
void HStreamRepeatUnitTest::SetUpTestCase(void) {}

void HStreamRepeatUnitTest::TearDownTestCase(void) {}

void HStreamRepeatUnitTest::TearDown(void) {}

void HStreamRepeatUnitTest::SetUp(void) {}

HStreamRepeat* HStreamRepeatUnitTest::CreateHStreamRepeat()
{
    sptr<OHOS::IConsumerSurface> cSurface = IConsumerSurface::Create();
    sptr<OHOS::IBufferProducer> producer = cSurface->GetProducer();
    int32_t format = 1;
    int32_t width = 1920;
    int32_t height = 1080;
    auto streamRepeat = new (std::nothrow)
        HStreamRepeat(producer, format, width, height, RepeatStreamType::PREVIEW);
    return streamRepeat;
}

/*
 * Feature: Framework
 * Function: Test SetStreamInfo
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the SetStreamInfo function when mEnableSecure is true.
 *    The extendedStreamInfos should not be empty after setting stream info.
 */
HWTEST_F(HStreamRepeatUnitTest, hstream_repeat_unittest_001, TestSize.Level0)
{
    auto streamRepeat = CreateHStreamRepeat();
    ASSERT_NE(streamRepeat, nullptr);
    StreamInfo_V1_1 streamInfo;
    streamRepeat->repeatStreamType_ = RepeatStreamType::PREVIEW;
    streamRepeat->mEnableSecure = true;
    streamRepeat->SetStreamInfo(streamInfo);
    EXPECT_FALSE(streamInfo.extendedStreamInfos.empty());
}

/*
 * Feature: Framework
 * Function: Test SetStreamInfo
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the SetStreamInfo function when mEnableSecure is false.
 *    The extendedStreamInfos should be empty after setting stream info.
 */
HWTEST_F(HStreamRepeatUnitTest, hstream_repeat_unittest_002, TestSize.Level0)
{
    auto streamRepeat = CreateHStreamRepeat();
    ASSERT_NE(streamRepeat, nullptr);
    StreamInfo_V1_1 streamInfo;
    streamRepeat->repeatStreamType_ = RepeatStreamType::PREVIEW;
    streamRepeat->mEnableSecure = false;
    streamRepeat->SetStreamInfo(streamInfo);
    EXPECT_TRUE(streamInfo.extendedStreamInfos.empty());
}

/*
 * Feature: Framework
 * Function: Test UpdateSketchStatus
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the UpdateSketchStatus function. When the sketch status is updated to STOPED,
 *    the parentStreamRepeat should remain unchanged.
 */
HWTEST_F(HStreamRepeatUnitTest, hstream_repeat_unittest_003, TestSize.Level0)
{
    auto streamRepeat = CreateHStreamRepeat();
    ASSERT_NE(streamRepeat, nullptr);
    SketchStatus status = SketchStatus::STOPED;
    streamRepeat->repeatStreamType_ = RepeatStreamType::SKETCH;
    streamRepeat->sketchStatus_ = SketchStatus::STARTED;
    streamRepeat->mEnableSecure = false;
    streamRepeat->UpdateSketchStatus(status);
    EXPECT_EQ(streamRepeat->parentStreamRepeat_.promote(), nullptr);
}

/*
 * Feature: Framework
 * Function: Test Start
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the Start function. When the stream is not in a valid state,
 *    the expected return value is CAMERA_INVALID_STATE.
 */
HWTEST_F(HStreamRepeatUnitTest, hstream_repeat_unittest_004, TestSize.Level0)
{
    auto streamRepeat = CreateHStreamRepeat();
    ASSERT_NE(streamRepeat, nullptr);
    std::shared_ptr<OHOS::Camera::CameraMetadata> settings;
    bool isUpdateSeetings = false;
    int32_t ret = streamRepeat->Start(settings, isUpdateSeetings);
    EXPECT_EQ(ret, CAMERA_INVALID_STATE);
}

/*
 * Feature: Framework
 * Function: Test ReleaseStream
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the ReleaseStream function.
 *    When the stream is released without delay, the expected return value is CAMERA_OK.
 */
HWTEST_F(HStreamRepeatUnitTest, hstream_repeat_unittest_005, TestSize.Level0)
{
    auto streamRepeat = CreateHStreamRepeat();
    ASSERT_NE(streamRepeat, nullptr);
    bool isDelay = false;
    int32_t ret = streamRepeat->ReleaseStream(isDelay);
    EXPECT_EQ(ret, CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test OnDeferredVideoEnhancementInfo
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the OnDeferredVideoEnhancementInfo function.
 * When the deferred video enhancement info is received,
 *    the expected return value is CAMERA_OK.
 */
HWTEST_F(HStreamRepeatUnitTest, hstream_repeat_unittest_006, TestSize.Level0)
{
    auto streamRepeat = CreateHStreamRepeat();
    ASSERT_NE(streamRepeat, nullptr);
    CaptureEndedInfoExt captureEndedInfo = {1, 100, true, "video123"};
    streamRepeat->repeatStreamType_ = RepeatStreamType::PREVIEW;
    int32_t ret = streamRepeat->OnDeferredVideoEnhancementInfo(captureEndedInfo);
    EXPECT_EQ(ret, CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test OnFrameError
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the OnFrameError function. When a frame error of type HIGH_TEMPERATURE_ERROR is reported,
 *    the expected return value is CAMERA_OK.
 */
HWTEST_F(HStreamRepeatUnitTest, hstream_repeat_unittest_007, TestSize.Level0)
{
    auto streamRepeat = CreateHStreamRepeat();
    ASSERT_NE(streamRepeat, nullptr);
    int32_t errorType = HDI::Camera::V1_3::HIGH_TEMPERATURE_ERROR;
    int32_t ret = streamRepeat->OnFrameError(errorType);
    EXPECT_EQ(ret, CAMERA_OK);
}


} // CameraStandard
} // OHOS