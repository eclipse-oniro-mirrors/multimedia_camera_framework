/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include "cfilter_unit_test.h"

#include <memory>

#include "cfilter.h"
#include "osal/task/task.h"

using namespace testing::ext;

namespace OHOS {
namespace CameraStandard {
void CFilterUnitTest::SetUpTestCase(void)
{
    std::cout << "[SetUpTestCase]: SetUp!!!" << std::endl;
}

void CFilterUnitTest::TearDownTestCase(void)
{
    std::cout << "[TearDownTestCase]: over!!!" << std::endl;
}

void CFilterUnitTest::SetUp(void)
{
    std::cout << "[SetUp]: SetUp!!!" << std::endl;
}

void CFilterUnitTest::TearDown(void)
{
    std::cout << "[TearDown]: over!!!" << std::endl;
}

/**
 * @tc.name: LinkPipline_001
 * @tc.desc: Test LinkPipline interface, set filtertype to AUDIO_ENC
 * @tc.type: FUNC
 */
HWTEST_F(CFilterUnitTest, LinkPipline_001, TestSize.Level1)
{
    std::shared_ptr<MockFilter> filter = std::make_shared<MockFilter>("testFilter", CFilterType::AUDIO_ENC, true);
    filter->Init(nullptr, nullptr);
    filter->LinkPipeLine("");
    EXPECT_EQ(CFilterState::INITIALIZED, filter->curState_);
}

/**
 * @tc.name: LinkPipline_002
 * @tc.desc: Test LinkPipline interface, set filtertype to AUDIO_DEC
 * @tc.type: FUNC
 */
HWTEST_F(CFilterUnitTest, LinkPipline_002, TestSize.Level1)
{
    std::shared_ptr<MockFilter> filter = std::make_shared<MockFilter>("testFilter", CFilterType::AUDIO_DEC, true);
    filter->Init(nullptr, nullptr);
    filter->LinkPipeLine("");
    EXPECT_EQ(CFilterState::INITIALIZED, filter->curState_);
}

/**
 * @tc.name: LinkPipline_003
 * @tc.desc: Test LinkPipline interface, set filtertype to VIDEO_ENC
 * @tc.type: FUNC
 */
HWTEST_F(CFilterUnitTest, LinkPipline_003, TestSize.Level1)
{
    std::shared_ptr<MockFilter> filter = std::make_shared<MockFilter>("testFilter", CFilterType::VIDEO_ENC, true);
    filter->Init(nullptr, nullptr);
    filter->LinkPipeLine("");
    EXPECT_EQ(CFilterState::INITIALIZED, filter->curState_);
}

/**
 * @tc.name: LinkPipline_004
 * @tc.desc: Test LinkPipline interface, set filtertype to VIDEO_DEC
 * @tc.type: FUNC
 */
HWTEST_F(CFilterUnitTest, LinkPipline_004, TestSize.Level1)
{
    std::shared_ptr<MockFilter> filter = std::make_shared<MockFilter>("testFilter", CFilterType::VIDEO_DEC, true);
    filter->Init(nullptr, nullptr);
    filter->LinkPipeLine("");
    EXPECT_EQ(CFilterState::INITIALIZED, filter->curState_);
}

/**
 * @tc.name: LinkPipline_005
 * @tc.desc: Test LinkPipline interface, set filtertype to AUDIO_CAPTURE
 * @tc.type: FUNC
 */
HWTEST_F(CFilterUnitTest, LinkPipline_005, TestSize.Level1)
{
    std::shared_ptr<MockFilter> filter = std::make_shared<MockFilter>("testFilter", CFilterType::AUDIO_CAPTURE, true);
    filter->Init(nullptr, nullptr);
    filter->LinkPipeLine("");
    EXPECT_EQ(CFilterState::INITIALIZED, filter->curState_);
}

/**
 * @tc.name: LinkPipline_006
 * @tc.desc: Test LinkPipline interface, set filtertype to DEMUXER
 * @tc.type: FUNC
 */
HWTEST_F(CFilterUnitTest, LinkPipline_006, TestSize.Level1)
{
    std::shared_ptr<MockFilter> filter = std::make_shared<MockFilter>("testFilter", CFilterType::DEMUXER, true);
    filter->Init(nullptr, nullptr);
    filter->LinkPipeLine("");
    EXPECT_EQ(CFilterState::INITIALIZED, filter->curState_);
}


/**
 * @tc.name: LinkPipline_007
 * @tc.desc: Test LinkPipline interface, set filtertype to MUXER
 * @tc.type: FUNC
 */
HWTEST_F(CFilterUnitTest, LinkPipline_007, TestSize.Level1)
{
    std::shared_ptr<MockFilter> filter = std::make_shared<MockFilter>("testFilter", CFilterType::MUXER, true);
    filter->Init(nullptr, nullptr);
    filter->LinkPipeLine("");
    EXPECT_EQ(CFilterState::INITIALIZED, filter->curState_);
}

/**
 * @tc.name: LinkPipline_008
 * @tc.desc: Test LinkPipline interface, set filtertype to TIMED_METADATA
 * @tc.type: FUNC
 */
HWTEST_F(CFilterUnitTest, LinkPipline_008, TestSize.Level1)
{
    std::shared_ptr<MockFilter> filter = std::make_shared<MockFilter>("testFilter", CFilterType::TIMED_METADATA, true);
    filter->Init(nullptr, nullptr);
    filter->LinkPipeLine("");
    EXPECT_EQ(CFilterState::INITIALIZED, filter->curState_);
}

/**
 * @tc.name: LinkPipline_false_001
 * @tc.desc: Test LinkPipline interface, set filtertype to AUDIO_ENC
 * @tc.type: FUNC
 */
HWTEST_F(CFilterUnitTest, LinkPipline_false_001, TestSize.Level1)
{
    std::shared_ptr<MockFilter> filter = std::make_shared<MockFilter>("testFilter", CFilterType::AUDIO_ENC, false);
    filter->Init(nullptr, nullptr);
    filter->LinkPipeLine("");
    EXPECT_EQ(CFilterState::INITIALIZED, filter->curState_);
}

/**
 * @tc.name: LinkPipline_false_002
 * @tc.desc: Test LinkPipline interface, set filtertype to AUDIO_DEC
 * @tc.type: FUNC
 */
HWTEST_F(CFilterUnitTest, LinkPipline_false_002, TestSize.Level1)
{
    std::shared_ptr<MockFilter> filter = std::make_shared<MockFilter>("testFilter", CFilterType::AUDIO_DEC, false);
    filter->Init(nullptr, nullptr);
    filter->LinkPipeLine("");
    EXPECT_EQ(CFilterState::INITIALIZED, filter->curState_);
}

/**
 * @tc.name: LinkPipline_false_003
 * @tc.desc: Test LinkPipline interface, set filtertype to VIDEO_ENC
 * @tc.type: FUNC
 */
HWTEST_F(CFilterUnitTest, LinkPipline_false_003, TestSize.Level1)
{
    std::shared_ptr<MockFilter> filter = std::make_shared<MockFilter>("testFilter", CFilterType::VIDEO_ENC, false);
    filter->Init(nullptr, nullptr);
    filter->LinkPipeLine("");
    EXPECT_EQ(CFilterState::INITIALIZED, filter->curState_);
}

/**
 * @tc.name: LinkPipline_false_004
 * @tc.desc: Test LinkPipline interface, set filtertype to VIDEO_DEC
 * @tc.type: FUNC
 */
HWTEST_F(CFilterUnitTest, LinkPipline_false_004, TestSize.Level1)
{
    std::shared_ptr<MockFilter> filter = std::make_shared<MockFilter>("testFilter", CFilterType::VIDEO_DEC, false);
    filter->Init(nullptr, nullptr);
    filter->LinkPipeLine("");
    EXPECT_EQ(CFilterState::INITIALIZED, filter->curState_);
}

/**
 * @tc.name: LinkPipline_false_005
 * @tc.desc: Test LinkPipline interface, set filtertype to AUDIO_CAPTURE
 * @tc.type: FUNC
 */
HWTEST_F(CFilterUnitTest, LinkPipline_false_005, TestSize.Level1)
{
    std::shared_ptr<MockFilter> filter = std::make_shared<MockFilter>("testFilter", CFilterType::AUDIO_CAPTURE, false);
    filter->Init(nullptr, nullptr);
    filter->LinkPipeLine("");
    EXPECT_EQ(CFilterState::INITIALIZED, filter->curState_);
}

/**
 * @tc.name: LinkPipline_false_006
 * @tc.desc: Test LinkPipline interface, set filtertype to DEMUXER
 * @tc.type: FUNC
 */
HWTEST_F(CFilterUnitTest, LinkPipline_false_006, TestSize.Level1)
{
    std::shared_ptr<MockFilter> filter = std::make_shared<MockFilter>("testFilter", CFilterType::DEMUXER, false);
    filter->Init(nullptr, nullptr);
    filter->LinkPipeLine("");
    EXPECT_EQ(CFilterState::INITIALIZED, filter->curState_);
}


/**
 * @tc.name: LinkPipline_false_007
 * @tc.desc: Test LinkPipline interface, set filtertype to MUXER
 * @tc.type: FUNC
 */
HWTEST_F(CFilterUnitTest, LinkPipline_false_007, TestSize.Level1)
{
    std::shared_ptr<MockFilter> filter = std::make_shared<MockFilter>("testFilter", CFilterType::MUXER, false);
    filter->Init(nullptr, nullptr);
    filter->LinkPipeLine("");
    EXPECT_EQ(CFilterState::INITIALIZED, filter->curState_);
}

/**
 * @tc.name: LinkPipline_false_008
 * @tc.desc: Test LinkPipline interface, set filtertype to TIMED_METADATA
 * @tc.type: FUNC
 */
HWTEST_F(CFilterUnitTest, LinkPipline_false_008, TestSize.Level1)
{
    std::shared_ptr<MockFilter> filter = std::make_shared<MockFilter>("testFilter", CFilterType::TIMED_METADATA, false);
    filter->Init(nullptr, nullptr);
    filter->LinkPipeLine("");
    EXPECT_EQ(CFilterState::INITIALIZED, filter->curState_);
}

/**
 * @tc.name: Prepare_001
 * @tc.desc: Test Prepare interface, set asyncMode to false
 * @tc.type: FUNC
 */
HWTEST_F(CFilterUnitTest, Prepare_001, TestSize.Level1)
{
    std::shared_ptr<MockFilter> filter = std::make_shared<MockFilter>("testFilter", CFilterType::VIDEO_ENC, false);
    filter->Init(nullptr, nullptr);
    filter->LinkPipeLine("");
    EXPECT_EQ(CFilterState::INITIALIZED, filter->curState_);
    filter->Prepare();
    EXPECT_EQ(CFilterState::READY, filter->curState_);
}

/**
 * @tc.name: Prepare_002
 * @tc.desc: Test Prepare interface, set asyncMode to true
 * @tc.type: FUNC
 */
HWTEST_F(CFilterUnitTest, Prepare_002, TestSize.Level1)
{
    std::shared_ptr<MockFilter> filter = std::make_shared<MockFilter>("testFilter", CFilterType::VIDEO_ENC, true);
    filter->Init(nullptr, nullptr);
    filter->LinkPipeLine("");
    filter->Prepare();
    EXPECT_EQ(CFilterState::READY, filter->curState_);
}

/**
 * @tc.name: Prepare_003
 * @tc.desc: Test Prepare interface, set state is error
 * @tc.type: FUNC
 */
HWTEST_F(CFilterUnitTest, Prepare_003, TestSize.Level1)
{
    std::shared_ptr<MockFilter> filter = std::make_shared<MockFilter>("testFilter", CFilterType::VIDEO_ENC, true);
    filter->Init(nullptr, nullptr);
    filter->LinkPipeLine("");
    filter->ChangeState(CFilterState::ERROR);
    filter->Prepare();
    EXPECT_EQ(CFilterState::ERROR, filter->curState_);
}

/**
 * @tc.name: PrepareDone_001
 * @tc.desc: Test PrepareDone interface
 * @tc.type: FUNC
 */
HWTEST_F(CFilterUnitTest, PrepareDone_001, TestSize.Level1)
{
    std::shared_ptr<MockFilter> filter = std::make_shared<MockFilter>("testFilter", CFilterType::VIDEO_ENC, false);
    std::shared_ptr<MockFilter> filter2 = std::make_shared<MockFilter>("testFilter", CFilterType::VIDEO_ENC, false);
    filter->Init(nullptr, nullptr);
    filter2->Init(nullptr, nullptr);
    filter->LinkPipeLine("");
    filter->nextCFiltersMap_[CStreamType::PACKED].push_back(filter2);
    filter->Prepare();
    EXPECT_EQ(CFilterState::READY, filter->curState_);
}

/**
 * @tc.name: PrepareDone_002
 * @tc.desc: Test PrepareDone interface
 * @tc.type: FUNC
 */
HWTEST_F(CFilterUnitTest, PrepareDone_002, TestSize.Level1)
{
    std::shared_ptr<MockFilter> filter = std::make_shared<MockFilter>("testFilter", CFilterType::VIDEO_ENC, true);
    std::shared_ptr<MockFilter> filter2 = std::make_shared<MockFilter>("testFilter", CFilterType::VIDEO_ENC, true);
    filter->Init(nullptr, nullptr);
    filter2->Init(nullptr, nullptr);
    filter->LinkPipeLine("");
    filter2->LinkPipeLine("");
    filter->nextCFiltersMap_[CStreamType::PACKED].push_back(filter2);
    filter->Prepare();
    EXPECT_EQ(CFilterState::READY, filter->curState_);
}

/**
 * @tc.name: Release_001
 * @tc.desc: Test Release interface
 * @tc.type: FUNC
 */
HWTEST_F(CFilterUnitTest, Release_001, TestSize.Level1)
{
    std::shared_ptr<MockFilter> filter = std::make_shared<MockFilter>("testFilter", CFilterType::VIDEO_ENC, false);
    std::shared_ptr<MockFilter> filter2 = std::make_shared<MockFilter>("testFilter", CFilterType::VIDEO_ENC, false);
    filter->Init(nullptr, nullptr);
    filter2->Init(nullptr, nullptr);
    filter->nextCFiltersMap_[CStreamType::PACKED].push_back(filter2);
    filter->LinkPipeLine("");
    EXPECT_EQ(Status::OK, filter->Start());
    EXPECT_EQ(Status::OK, filter->Pause());
    EXPECT_EQ(Status::OK, filter->Resume());
    EXPECT_EQ(Status::OK, filter->Stop());
    EXPECT_EQ(Status::OK, filter->Release());
    sleep(sleepTime_);
}

/**
 * @tc.name: Release_002
 * @tc.desc: Test Release interface
 * @tc.type: FUNC
 */
HWTEST_F(CFilterUnitTest, Release_002, TestSize.Level1)
{
    std::shared_ptr<MockFilter> filter = std::make_shared<MockFilter>("testFilter", CFilterType::VIDEO_ENC, true);
    std::shared_ptr<MockFilter> filter2 = std::make_shared<MockFilter>("testFilter", CFilterType::VIDEO_ENC, true);
    filter->Init(nullptr, nullptr);
    filter2->Init(nullptr, nullptr);
    filter->nextCFiltersMap_[CStreamType::PACKED].push_back(filter2);
    filter->LinkPipeLine("");
    filter->filterTask_ = std::make_unique<Media::Task>("test");
    EXPECT_EQ(Status::OK, filter->Start());
    EXPECT_EQ(Status::OK, filter->Pause());
    EXPECT_EQ(Status::OK, filter->Resume());
    EXPECT_EQ(Status::OK, filter->Stop());
    EXPECT_EQ(Status::OK, filter->Release());
    sleep(sleepTime_);
}

/**
 * @tc.name: InputOutputBuffer_001
 * @tc.desc: Test ProcessInputBuffer and ProcessInOutputBuffer interface
 * @tc.type: FUNC
 */
HWTEST_F(CFilterUnitTest, InputOutputBuffer_001, TestSize.Level1)
{
    std::shared_ptr<MockFilter> filter = std::make_shared<MockFilter>("testFilter", CFilterType::VIDEO_ENC, true);
    std::shared_ptr<MockFilter> filter2 = std::make_shared<MockFilter>("testFilter", CFilterType::VIDEO_ENC, true);
    filter->Init(nullptr, nullptr);
    filter2->Init(nullptr, nullptr);
    filter->nextCFiltersMap_[CStreamType::PACKED].push_back(filter2);
    filter->LinkPipeLine("");
    EXPECT_EQ(Status::OK, filter->ProcessInputBuffer(0, 0));
    EXPECT_EQ(Status::OK, filter->ProcessOutputBuffer(0, 0));
}

/**
 * @tc.name: WaitAllState_001
 * @tc.desc: Test WaitAllState interface, wait PREPARING error
 * @tc.type: FUNC
 */
HWTEST_F(CFilterUnitTest, WaitAllState_001, TestSize.Level1)
{
    std::shared_ptr<MockFilter> filter = std::make_shared<MockFilter>("testFilter", CFilterType::VIDEO_ENC, true);
    std::shared_ptr<MockFilter> filter2 = std::make_shared<MockFilter>("testFilter", CFilterType::VIDEO_ENC, true);
    filter->Init(nullptr, nullptr);
    filter2->Init(nullptr, nullptr);
    filter->nextCFiltersMap_[CStreamType::PACKED].push_back(filter2);
    filter->LinkPipeLine("");
    EXPECT_NE(Status::OK, filter->WaitAllState(CFilterState::PREPARING));
}

/**
 * @tc.name: WaitAllState_002
 * @tc.desc: Test WaitAllState interface, wait INITIALIZED timeout
 * @tc.type: FUNC
 */
HWTEST_F(CFilterUnitTest, WaitAllState_002, TestSize.Level1)
{
    std::shared_ptr<MockFilter> filter = std::make_shared<MockFilter>("testFilter", CFilterType::VIDEO_ENC, true);
    std::shared_ptr<MockFilter> filter2 = std::make_shared<MockFilter>("testFilter", CFilterType::VIDEO_ENC, true);
    filter->Init(nullptr, nullptr);
    filter2->Init(nullptr, nullptr);
    filter->nextCFiltersMap_[CStreamType::PACKED].push_back(filter2);
    EXPECT_NE(Status::OK, filter->WaitAllState(CFilterState::INITIALIZED));
}

/**
 * @tc.name: WaitAllState_003
 * @tc.desc: Test WaitAllState interface, wait INITIALIZED success
 * @tc.type: FUNC
 */
HWTEST_F(CFilterUnitTest, WaitAllState_003, TestSize.Level1)
{
    std::shared_ptr<MockFilter> filter = std::make_shared<MockFilter>("testFilter", CFilterType::VIDEO_ENC, true);
    std::shared_ptr<MockFilter> filter2 = std::make_shared<MockFilter>("testFilter", CFilterType::VIDEO_ENC, true);
    filter->Init(nullptr, nullptr);
    filter2->Init(nullptr, nullptr);
    filter->nextCFiltersMap_[CStreamType::PACKED].push_back(filter2);
    filter->LinkPipeLine("");
    filter2->LinkPipeLine("");
    EXPECT_EQ(Status::OK, filter->WaitAllState(CFilterState::INITIALIZED));
}

/**
 * @tc.name: WaitAllState_004
 * @tc.desc: Test WaitAllState interface, isAsyncMode_ is false
 * @tc.type: FUNC
 */
HWTEST_F(CFilterUnitTest, WaitAllState_004, TestSize.Level1)
{
    std::shared_ptr<MockFilter> filter = std::make_shared<MockFilter>("testFilter", CFilterType::VIDEO_ENC, false);
    std::shared_ptr<MockFilter> filter2 = std::make_shared<MockFilter>("testFilter", CFilterType::VIDEO_ENC, false);
    filter->Init(nullptr, nullptr);
    filter2->Init(nullptr, nullptr);
    filter->nextCFiltersMap_[CStreamType::PACKED].push_back(filter2);
    filter->LinkPipeLine("");
    filter2->LinkPipeLine("");
    EXPECT_EQ(CFilterState::INITIALIZED, filter->curState_);
    EXPECT_EQ(Status::OK, filter->WaitAllState(CFilterState::INITIALIZED));
}

/**
 * @tc.name: Pause_001
 * @tc.desc: Test Release interface
 * @tc.type: FUNC
 */
HWTEST_F(CFilterUnitTest, Pause_001, TestSize.Level1)
{
    std::shared_ptr<MockFilter> filter = std::make_shared<MockFilter>("testFilter", CFilterType::VIDEO_ENC, true);
    std::shared_ptr<MockFilter> filter2 = std::make_shared<MockFilter>("testFilter", CFilterType::VIDEO_ENC, true);
    filter->Init(nullptr, nullptr);
    filter2->Init(nullptr, nullptr);
    filter->nextCFiltersMap_[CStreamType::PACKED].push_back(filter2);
    filter->LinkPipeLine("");
    EXPECT_EQ(Status::OK, filter->Start());
    EXPECT_EQ(Status::OK, filter->PauseDragging());
    EXPECT_EQ(Status::OK, filter->PauseAudioAlign());
    EXPECT_EQ(Status::OK, filter->Stop());
    EXPECT_EQ(Status::OK, filter->Release());
    sleep(sleepTime_);
}

/**
 * @tc.name: Pause_002
 * @tc.desc: Test Release interface
 * @tc.type: FUNC
 */
HWTEST_F(CFilterUnitTest, Pause_002, TestSize.Level1)
{
    std::shared_ptr<MockFilter> filter = std::make_shared<MockFilter>("testFilter", CFilterType::VIDEO_ENC, true);
    std::shared_ptr<MockFilter> filter2 = std::make_shared<MockFilter>("testFilter", CFilterType::VIDEO_ENC, true);
    filter->Init(nullptr, nullptr);
    filter2->Init(nullptr, nullptr);
    filter->nextCFiltersMap_[CStreamType::PACKED].push_back(filter2);
    filter->LinkPipeLine("");
    EXPECT_EQ(Status::OK, filter->PauseDragging());
    EXPECT_EQ(Status::OK, filter->PauseAudioAlign());
    EXPECT_EQ(Status::OK, filter->Stop());
    EXPECT_EQ(Status::OK, filter->Release());
    sleep(sleepTime_);
}

/**
 * @tc.name: Resume_001
 * @tc.desc: Test Release interface
 * @tc.type: FUNC
 */
HWTEST_F(CFilterUnitTest, Resume_001, TestSize.Level1)
{
    std::shared_ptr<MockFilter> filter = std::make_shared<MockFilter>("testFilter", CFilterType::VIDEO_ENC, true);
    std::shared_ptr<MockFilter> filter2 = std::make_shared<MockFilter>("testFilter", CFilterType::VIDEO_ENC, true);
    filter->Init(nullptr, nullptr);
    filter2->Init(nullptr, nullptr);
    filter->nextCFiltersMap_[CStreamType::PACKED].push_back(filter2);
    filter->LinkPipeLine("");
    EXPECT_EQ(Status::OK, filter->Start());
    EXPECT_EQ(Status::OK, filter->ResumeDragging());
    EXPECT_EQ(Status::OK, filter->ResumeAudioAlign());
    EXPECT_EQ(Status::OK, filter->Stop());
    EXPECT_EQ(Status::OK, filter->Release());
    sleep(sleepTime_);
}

/**
 * @tc.name: Resume_002
 * @tc.desc: Test Release interface
 * @tc.type: FUNC
 */
HWTEST_F(CFilterUnitTest, Resume_002, TestSize.Level1)
{
    std::shared_ptr<MockFilter> filter = std::make_shared<MockFilter>("testFilter", CFilterType::VIDEO_ENC, true);
    std::shared_ptr<MockFilter> filter2 = std::make_shared<MockFilter>("testFilter", CFilterType::VIDEO_ENC, true);
    filter->Init(nullptr, nullptr);
    filter2->Init(nullptr, nullptr);
    filter->nextCFiltersMap_[CStreamType::PACKED].push_back(filter2);
    filter->LinkPipeLine("");
    EXPECT_EQ(Status::OK, filter->ResumeDragging());
    EXPECT_EQ(Status::OK, filter->ResumeAudioAlign());
    EXPECT_EQ(Status::OK, filter->Stop());
    EXPECT_EQ(Status::OK, filter->Release());
    sleep(sleepTime_);
}

/**
 * @tc.name: Flush_001
 * @tc.desc: Test Release interface
 * @tc.type: FUNC
 */
HWTEST_F(CFilterUnitTest, Flush_001, TestSize.Level1)
{
    std::shared_ptr<MockFilter> filter = std::make_shared<MockFilter>("testFilter", CFilterType::VIDEO_ENC, true);
    std::shared_ptr<MockFilter> filter2 = std::make_shared<MockFilter>("testFilter", CFilterType::VIDEO_ENC, true);
    filter->Init(nullptr, nullptr);
    filter2->Init(nullptr, nullptr);
    filter->nextCFiltersMap_[CStreamType::PACKED].push_back(filter2);
    filter->LinkPipeLine("");
    EXPECT_EQ(Status::OK, filter->Start());
    EXPECT_EQ(Status::OK, filter->Flush());
    EXPECT_EQ(Status::OK, filter->Stop());
    EXPECT_EQ(Status::OK, filter->Release());
    sleep(sleepTime_);
}

/**
 * @tc.name: SetPlayRange_001
 * @tc.desc: Test Release interface
 * @tc.type: FUNC
 */
HWTEST_F(CFilterUnitTest, SetPlayRange_001, TestSize.Level1)
{
    std::shared_ptr<MockFilter> filter = std::make_shared<MockFilter>("testFilter", CFilterType::VIDEO_ENC, true);
    std::shared_ptr<MockFilter> filter2 = std::make_shared<MockFilter>("testFilter", CFilterType::VIDEO_ENC, true);
    filter->Init(nullptr, nullptr);
    filter2->Init(nullptr, nullptr);
    filter->nextCFiltersMap_[CStreamType::PACKED].push_back(filter2);
    filter->LinkPipeLine("");
    EXPECT_EQ(Status::OK, filter->Start());
    EXPECT_EQ(Status::OK, filter->SetPlayRange(0, 1));
    EXPECT_EQ(Status::OK, filter->Stop());
    EXPECT_EQ(Status::OK, filter->Release());
    sleep(sleepTime_);
}
} // namespace CameraStandard
} // namespace OHOS