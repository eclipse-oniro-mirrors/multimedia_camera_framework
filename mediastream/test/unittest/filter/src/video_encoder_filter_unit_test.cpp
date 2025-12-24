/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

#include "video_encoder_filter_unit_test.h"

namespace OHOS {
namespace CameraStandard {

using namespace testing;
using namespace testing::ext;

void VideoEncoderFilterUnitTest::SetUpTestCase(void)
{
    std::cout << "[SetUpTestCase] is called" << std::endl;
}

void VideoEncoderFilterUnitTest::TearDownTestCase(void)
{
    std::cout << "[TearDownTestCase] is called" << std::endl;
}

void VideoEncoderFilterUnitTest::SetUp()
{
    std::cout << "[SetUp] is called" << std::endl;
    videoEncoder_ = std::make_shared<VideoEncoderFilter>("test", CFilterType::VIDEO_ENC);
}

void VideoEncoderFilterUnitTest::TearDown()
{
    std::cout << "[TearDown] is called" << std::endl;
    videoEncoder_.reset();
}

/*
 * Feature: VideoEncoderFilter
 * CaseDescription: Test SetCodecFormat method success
 */
HWTEST_F(VideoEncoderFilterUnitTest, SetCodecFormat_001, TestSize.Level1)
{
    std::shared_ptr<Meta> format = std::make_shared<Meta>();
    format->Set<Tag::MIME_TYPE>("test");
    Status result =  videoEncoder_->SetCodecFormat(format);
    EXPECT_EQ(result, Status::OK);
}

/*
 * Feature: VideoEncoderFilter
 * CaseDescription: Test SetCodecFormat method failed
 */
HWTEST_F(VideoEncoderFilterUnitTest, SetCodecFormat_002, TestSize.Level1)
{
    std::shared_ptr<Meta> format = std::make_shared<Meta>();
    Status result =  videoEncoder_->SetCodecFormat(format);
    EXPECT_EQ(result, Status::ERROR_INVALID_PARAMETER);
}

/*
 * Feature: VideoEncoderFilter
 * CaseDescription: Test Init method
 */
HWTEST_F(VideoEncoderFilterUnitTest, Init_001, TestSize.Level1)
{
    videoEncoder_->mediaCodec_ = std::make_shared<VideoEncoderAdapter>();
    videoEncoder_->Init(nullptr, nullptr);
    EXPECT_EQ(videoEncoder_->isUpdateCodecNeeded_, false);
}

/*
 * Feature: VideoEncoderFilter
 * CaseDescription: Test Configure method
 */
HWTEST_F(VideoEncoderFilterUnitTest, Configure_001, TestSize.Level1)
{
    std::shared_ptr<Meta> format = std::make_shared<Meta>();
    Status result =  videoEncoder_->Configure(format);
    EXPECT_NE(result, Status::OK);
}

/*
 * Feature: VideoEncoderFilter
 * CaseDescription: Test SetWatermark method
 */
HWTEST_F(VideoEncoderFilterUnitTest, SetWatermark_001, TestSize.Level1)
{
    std::shared_ptr<AVBuffer> waterMarkBuffer = std::make_shared<AVBuffer>();
    Status result =  videoEncoder_->SetWatermark(waterMarkBuffer);
    EXPECT_NE(result, Status::OK);
}

/*
 * Feature: VideoEncoderFilter
 * CaseDescription: Test SetStopTime method
 */
HWTEST_F(VideoEncoderFilterUnitTest, SetStopTime_001, TestSize.Level1)
{
    Status result =  videoEncoder_->SetStopTime();
    EXPECT_NE(result, Status::OK);
}

/*
 * Feature: VideoEncoderFilter
 * CaseDescription: Test DoPrepare method
 */
HWTEST_F(VideoEncoderFilterUnitTest, DoPrepare_001, TestSize.Level1)
{
    Status result =  videoEncoder_->DoPrepare();
    EXPECT_NE(result, Status::OK);
}

/*
 * Feature: VideoEncoderFilter
 * CaseDescription: Test DoStart method
 */
HWTEST_F(VideoEncoderFilterUnitTest, DoStart_001, TestSize.Level1)
{
    Status result =  videoEncoder_->DoStart();
    EXPECT_NE(result, Status::OK);
}

/*
 * Feature: VideoEncoderFilter
 * CaseDescription: Test DoPause method
 */
HWTEST_F(VideoEncoderFilterUnitTest, DoPause_001, TestSize.Level1)
{
    Status result =  videoEncoder_->DoPause();
    EXPECT_NE(result, Status::OK);
}

/*
 * Feature: VideoEncoderFilter
 * CaseDescription: Test DoResume method
 */
HWTEST_F(VideoEncoderFilterUnitTest, DoResume_001, TestSize.Level1)
{
    Status result =  videoEncoder_->DoResume();
    EXPECT_NE(result, Status::OK);
}

/*
 * Feature: VideoEncoderFilter
 * CaseDescription: Test DoStop method
 */
HWTEST_F(VideoEncoderFilterUnitTest, DoStop_001, TestSize.Level1)
{
    Status result =  videoEncoder_->DoStop();
    EXPECT_EQ(result, Status::OK);
}

/*
 * Feature: VideoEncoderFilter
 * CaseDescription: Test DoRelease method
 */
HWTEST_F(VideoEncoderFilterUnitTest, DoRelease_001, TestSize.Level1)
{
    Status result =  videoEncoder_->DoRelease();
    EXPECT_EQ(result, Status::OK);
}

/*
 * Feature: VideoEncoderFilter
 * CaseDescription: Test NotifyEos method
 */
HWTEST_F(VideoEncoderFilterUnitTest, NotifyEos_001, TestSize.Level1)
{
    int64_t pts = -1;
    Status result =  videoEncoder_->NotifyEos(pts);
    EXPECT_NE(result, Status::OK);
}

/*
 * Feature: VideoEncoderFilter
 * CaseDescription: Test LinkNext method
 */
HWTEST_F(VideoEncoderFilterUnitTest, LinkNext_001, TestSize.Level1)
{
    std::shared_ptr<MockNextFilter> nextFilter = std::make_shared<MockNextFilter>();
    EXPECT_CALL(*nextFilter, OnLinked(_, _, _)).WillOnce(Return(Status::OK));
    Status result =  videoEncoder_->LinkNext(nextFilter, CStreamType::MAX);
    EXPECT_EQ(result, Status::OK);
}

/*
 * Feature: VideoEncoderFilter
 * CaseDescription: Test UpdateNext method
 */
HWTEST_F(VideoEncoderFilterUnitTest, UpdateNext_001, TestSize.Level1)
{
    std::shared_ptr<MockNextFilter> nextFilter = std::make_shared<MockNextFilter>();
    Status result =  videoEncoder_->UpdateNext(nextFilter, CStreamType::MAX);
    EXPECT_EQ(result, Status::OK);
}

/*
 * Feature: VideoEncoderFilter
 * CaseDescription: Test UnLinkNext method
 */
HWTEST_F(VideoEncoderFilterUnitTest, UnLinkNext_001, TestSize.Level1)
{
    std::shared_ptr<MockNextFilter> nextFilter = std::make_shared<MockNextFilter>();
    Status result =  videoEncoder_->UnLinkNext(nextFilter, CStreamType::MAX);
    EXPECT_EQ(result, Status::OK);
}

/*
 * Feature: VideoEncoderFilter
 * CaseDescription: Test GetFilterType method
 */
HWTEST_F(VideoEncoderFilterUnitTest, GetFilterType_001, TestSize.Level1)
{
    CFilterType result =  videoEncoder_->GetFilterType();
    EXPECT_NE(result, CFilterType::MAX);
}

/*
 * Feature: VideoEncoderFilter
 * CaseDescription: Test OnLinked method
 */
HWTEST_F(VideoEncoderFilterUnitTest, OnLinked_001, TestSize.Level1)
{
    std::shared_ptr<Meta> format = std::make_shared<Meta>();
    Status result =  videoEncoder_->OnLinked(CStreamType::MAX, format, nullptr);
    EXPECT_EQ(result, Status::OK);
}

/*
 * Feature: VideoEncoderFilter
 * CaseDescription: Test OnUpdated method
 */
HWTEST_F(VideoEncoderFilterUnitTest, OnUpdated_001, TestSize.Level1)
{
    std::shared_ptr<Meta> format = std::make_shared<Meta>();
    Status result =  videoEncoder_->OnUpdated(CStreamType::MAX, format, nullptr);
    EXPECT_EQ(result, Status::OK);
}

/*
 * Feature: VideoEncoderFilter
 * CaseDescription: Test OnUnLinked method
 */
HWTEST_F(VideoEncoderFilterUnitTest, OnUnLinked_001, TestSize.Level1)
{
    std::shared_ptr<Meta> format = std::make_shared<Meta>();
    Status result =  videoEncoder_->OnUnLinked(CStreamType::MAX, nullptr);
    EXPECT_EQ(result, Status::OK);
}

/*
 * Feature: VideoEncoderFilter
 * CaseDescription: Test OnLinkedResult method
 */
HWTEST_F(VideoEncoderFilterUnitTest, OnLinkedResult_001, TestSize.Level1)
{
    std::shared_ptr<Meta> format = std::make_shared<Meta>();
    videoEncoder_->OnLinkedResult(nullptr, format);
    EXPECT_EQ(videoEncoder_->instanceId_, 0);
}

/*
 * Feature: VideoEncoderFilter
 * CaseDescription: Test GetStopTimestamp method
 */
HWTEST_F(VideoEncoderFilterUnitTest, GetStopTimestamp_001, TestSize.Level1)
{
    std::shared_ptr<Meta> format = std::make_shared<Meta>();
    int64_t result = videoEncoder_->GetStopTimestamp();
    EXPECT_EQ(result, -1);
}
}
}