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

#include "avcodec_task_manager_unittest.h"

#include "avcodec_task_manager.h"
#include "camera_dynamic_loader.h"
#include "camera_log.h"
#include "camera_util.h"
#include "capture_scene_const.h"
#include "ipc_skeleton.h"

using namespace testing::ext;

static const int64_t VIDEO_FRAMERATE = 1280;

void MyFunction()
{
    MEDIA_DEBUG_LOG("MyFunction started!");
}

namespace OHOS {
namespace CameraStandard {

void AvcodecTaskManagerUnitTest::SetUpTestCase(void)
{
    MEDIA_DEBUG_LOG("AvcodecTaskManagerUnitTest::SetUpTestCase started!");
}

void AvcodecTaskManagerUnitTest::TearDownTestCase(void)
{
    MEDIA_DEBUG_LOG("AvcodecTaskManagerUnitTest::TearDownTestCase started!");
}

void AvcodecTaskManagerUnitTest::SetUp()
{
    MEDIA_DEBUG_LOG("AvcodecTaskManagerUnitTest::SetUp started!");
}

void AvcodecTaskManagerUnitTest::TearDown()
{
    MEDIA_DEBUG_LOG("AvcodecTaskManagerUnitTest::TearDown started!");
}

/*
 * Feature: Framework
 * Function: Test WriteSampleBuffer abnormal branches.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test WriteSampleBuffer abnormal branches.
 */
HWTEST_F(AvcodecTaskManagerUnitTest, avcodec_task_manager_unittest_001, TestSize.Level1)
{
    sptr<AudioCapturerSession> session = new AudioCapturerSession();
    VideoCodecType type = VideoCodecType::VIDEO_ENCODE_TYPE_AVC;
    ColorSpace colorSpace = ColorSpace::DISPLAY_P3;
    sptr<AvcodecTaskManager> taskManager = new AvcodecTaskManager(session, type, colorSpace);

    shared_ptr<TaskManager> manager = taskManager->GetTaskManager();
    ASSERT_NE(manager, nullptr);
    taskManager->taskManager_ = make_unique<TaskManager>("AvcodecTaskManager", DEFAULT_THREAD_NUMBER, false);
    manager = taskManager->GetTaskManager();
    ASSERT_NE(manager, nullptr);

    manager = taskManager->GetEncoderManager();
    ASSERT_NE(manager, nullptr);
    taskManager->videoEncoderManager_ = make_unique<TaskManager>
        ("VideoTaskManager", DEFAULT_ENCODER_THREAD_NUMBER, true);
    manager = taskManager->GetEncoderManager();
    ASSERT_NE(manager, nullptr);
    taskManager->SubmitTask(MyFunction);
    taskManager->videoEncoder_ = nullptr;
    taskManager->audioEncoder_ = make_unique<AudioEncoder>();
}

/*
 * Feature: Framework
 * Function: Test HdiToServiceError normal branches with different parameters.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test HdiToServiceError normal branches with different parameters.
 */
HWTEST_F(AvcodecTaskManagerUnitTest, avcodec_task_manager_unittest_002, TestSize.Level1)
{
    sptr<AudioCapturerSession> session = new AudioCapturerSession();
    VideoCodecType type = VideoCodecType::VIDEO_ENCODE_TYPE_AVC;
    ColorSpace colorSpace = ColorSpace::DISPLAY_P3;
    sptr<AvcodecTaskManager> taskManager = new AvcodecTaskManager(session, type, colorSpace);

    vector<sptr<FrameRecord>> frameRecords;
    uint64_t taskName = 1;
    int32_t captureRotation = 1;
    int32_t captureId = 1;
    taskManager->DoMuxerVideo(frameRecords, taskName, captureRotation, captureId);
    EXPECT_TRUE(frameRecords.empty());
    taskManager->videoEncoder_ = make_unique<VideoEncoder>(type, colorSpace);
    taskManager->audioEncoder_ = nullptr;
}

/*
 * Feature: Framework
 * Function: Test CollectAudioBuffer abnormal branches.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CollectAudioBuffer abnormal branches.
 */
HWTEST_F(AvcodecTaskManagerUnitTest, avcodec_task_manager_unittest_003, TestSize.Level1)
{
    sptr<AudioCapturerSession> session = new AudioCapturerSession();
    VideoCodecType type = VideoCodecType::VIDEO_ENCODE_TYPE_AVC;
    ColorSpace colorSpace = ColorSpace::DISPLAY_P3;
    sptr<AvcodecTaskManager> taskManager = new AvcodecTaskManager(session, type, colorSpace);

    vector<sptr<FrameRecord>> frameRecords;
    vector<sptr<FrameRecord>> choosedBuffer;
    int64_t shutterTime = 1;
    int32_t captureId = 1;
    taskManager->ChooseVideoBuffer(frameRecords, choosedBuffer, shutterTime, captureId);
    EXPECT_EQ(choosedBuffer.size(), 0);
    vector<sptr<AudioRecord>> audioRecordVec;
    sptr<AudioVideoMuxer> muxer;
    taskManager->CollectAudioBuffer(audioRecordVec, muxer);
    EXPECT_EQ(audioRecordVec.size(), 0);
}

/*
 * Feature: Framework
 * Function: Test Stop abnormal branches while videoEncoder_ is nullptr.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test Stop abnormal branches while videoEncoder_ is nullptr.
 */
HWTEST_F(AvcodecTaskManagerUnitTest, avcodec_task_manager_unittest_004, TestSize.Level1)
{
    sptr<AudioCapturerSession> session = new AudioCapturerSession();
    VideoCodecType type = VideoCodecType::VIDEO_ENCODE_TYPE_AVC;
    ColorSpace colorSpace = ColorSpace::DISPLAY_P3;
    sptr<AvcodecTaskManager> taskManager = new AvcodecTaskManager(session, type, colorSpace);

    taskManager->videoEncoder_ = nullptr;
    taskManager->audioEncoder_ = make_unique<AudioEncoder>();
    taskManager->Stop();
    EXPECT_FALSE(taskManager->audioEncoder_->isStarted_);
}

/*
 * Feature: Framework
 * Function: Test Stop abnormal branches while audioEncoder_ is nullptr.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test Stop abnormal branches while audioEncoder_ is nullptr.
 */
HWTEST_F(AvcodecTaskManagerUnitTest, avcodec_task_manager_unittest_005, TestSize.Level1)
{
    sptr<AudioCapturerSession> session = new AudioCapturerSession();
    VideoCodecType type = VideoCodecType::VIDEO_ENCODE_TYPE_AVC;
    ColorSpace colorSpace = ColorSpace::DISPLAY_P3;
    sptr<AvcodecTaskManager> taskManager = new AvcodecTaskManager(session, type, colorSpace);

    taskManager->videoEncoder_ = make_unique<VideoEncoder>(type, colorSpace);
    taskManager->audioEncoder_ = nullptr;
    taskManager->Stop();
    EXPECT_FALSE(taskManager->videoEncoder_->isStarted_);
}

/*
 * Feature: Framework
 * Function: Test GetTaskManager abnormal branches.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetTaskManager abnormal branches.
 */
HWTEST_F(AvcodecTaskManagerUnitTest, avcodec_task_manager_unittest_006, TestSize.Level1)
{
    sptr<AudioCapturerSession> session = new AudioCapturerSession();
    VideoCodecType type = VideoCodecType::VIDEO_ENCODE_TYPE_AVC;
    ColorSpace colorSpace = ColorSpace::DISPLAY_P3;
    sptr<AvcodecTaskManager> taskManager = new AvcodecTaskManager(session, type, colorSpace);

    taskManager->isActive_ = false;
    shared_ptr<TaskManager> manager = taskManager->GetTaskManager();
    EXPECT_EQ(manager, nullptr);
    taskManager->SubmitTask(MyFunction);

    taskManager->taskManager_ = make_unique<TaskManager>("AvcodecTaskManager", DEFAULT_THREAD_NUMBER, false);
    manager = taskManager->GetTaskManager();
    ASSERT_NE(manager, nullptr);
    taskManager->SubmitTask(MyFunction);
}

/*
 * Feature: Framework
 * Function: Test GetEncoderManager abnormal branches.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetEncoderManager abnormal branches.
 */
HWTEST_F(AvcodecTaskManagerUnitTest, avcodec_task_manager_unittest_007, TestSize.Level1)
{
    sptr<AudioCapturerSession> session = new AudioCapturerSession();
    VideoCodecType type = VideoCodecType::VIDEO_ENCODE_TYPE_AVC;
    ColorSpace colorSpace = ColorSpace::DISPLAY_P3;
    sptr<AvcodecTaskManager> taskManager = new AvcodecTaskManager(session, type, colorSpace);

    taskManager->isActive_ = false;
    shared_ptr<TaskManager> manager = taskManager->GetEncoderManager();
    EXPECT_EQ(manager, nullptr);

    taskManager->videoEncoderManager_ = make_unique<TaskManager>
        ("VideoTaskManager", DEFAULT_ENCODER_THREAD_NUMBER, true);
    manager = taskManager->GetEncoderManager();
    ASSERT_NE(manager, nullptr);
}

/*
 * Feature: Framework
 * Function: Test IgnoreDeblur when frameRecords is empty.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test IgnoreDeblur when frameRecords is empty.
 */
HWTEST_F(AvcodecTaskManagerUnitTest, avcodec_task_manager_unittest_008, TestSize.Level1)
{
    sptr<AudioCapturerSession> session = new AudioCapturerSession();
    VideoCodecType type = VideoCodecType::VIDEO_ENCODE_TYPE_AVC;
    ColorSpace colorSpace = ColorSpace::DISPLAY_P3;
    sptr<AvcodecTaskManager> taskManager = new AvcodecTaskManager(session, type, colorSpace);

    vector<sptr<FrameRecord>> frameRecords;
    vector<sptr<FrameRecord>> choosedBuffer;
    int64_t shutterTime = 100;

    taskManager->IgnoreDeblur(frameRecords, choosedBuffer, shutterTime);
    EXPECT_TRUE(choosedBuffer.empty());
}

/*
 * Feature: Framework
 * Function: Test IgnoreDeblur when frameRecords is not empty.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test IgnoreDeblur when frameRecords is not empty.
 */
HWTEST_F(AvcodecTaskManagerUnitTest, avcodec_task_manager_unittest_009, TestSize.Level1)
{
    sptr<AudioCapturerSession> session = new AudioCapturerSession();
    VideoCodecType type = VideoCodecType::VIDEO_ENCODE_TYPE_AVC;
    ColorSpace colorSpace = ColorSpace::DISPLAY_P3;
    sptr<AvcodecTaskManager> taskManager = new AvcodecTaskManager(session, type, colorSpace);

    vector<sptr<FrameRecord>> frameRecords;
    vector<sptr<FrameRecord>> choosedBuffer;
    int64_t shutterTime = 100;

    sptr<SurfaceBuffer> videoBuffer = SurfaceBuffer::Create();
    ASSERT_NE(videoBuffer, nullptr);
    int64_t timestamp = VIDEO_FRAMERATE;
    GraphicTransformType graphicType = GRAPHIC_ROTATE_90;
    sptr<FrameRecord> frameRecord =
        new(std::nothrow) FrameRecord(videoBuffer, timestamp, graphicType);
    ASSERT_NE(frameRecord, nullptr);
    frameRecord->SetIDRProperty(false);

    frameRecords.push_back(frameRecord);
    taskManager->IgnoreDeblur(frameRecords, choosedBuffer, shutterTime);
    EXPECT_TRUE(choosedBuffer.empty());
}

/*
 * Feature: Framework
 * Function: Test IgnoreDeblur when frameRecords is not empty and has IDR frame.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test IgnoreDeblur when frameRecords is not empty and has IDR frame.
 */
HWTEST_F(AvcodecTaskManagerUnitTest, avcodec_task_manager_unittest_010, TestSize.Level1)
{
    sptr<AudioCapturerSession> session = new AudioCapturerSession();
    VideoCodecType type = VideoCodecType::VIDEO_ENCODE_TYPE_AVC;
    ColorSpace colorSpace = ColorSpace::DISPLAY_P3;
    sptr<AvcodecTaskManager> taskManager = new AvcodecTaskManager(session, type, colorSpace);

    vector<sptr<FrameRecord>> frameRecords;
    vector<sptr<FrameRecord>> choosedBuffer;
    int64_t shutterTime = 100;

    sptr<SurfaceBuffer> videoBuffer = SurfaceBuffer::Create();
    ASSERT_NE(videoBuffer, nullptr);
    int64_t timestamp = VIDEO_FRAMERATE;
    GraphicTransformType graphicType = GRAPHIC_ROTATE_90;
    sptr<FrameRecord> frameRecord =
        new(std::nothrow) FrameRecord(videoBuffer, timestamp, graphicType);
    ASSERT_NE(frameRecord, nullptr);
    frameRecord->SetIDRProperty(true);

    frameRecords.push_back(frameRecord);
    taskManager->IgnoreDeblur(frameRecords, choosedBuffer, shutterTime);
    EXPECT_FALSE(choosedBuffer.empty());
}

/*
 * Feature: Framework
 * Function: Test Release abnormal branches when videoEncoder_ is not nullptr.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test Release abnormal branches when videoEncoder_ is not nullptr.
 */
HWTEST_F(AvcodecTaskManagerUnitTest, avcodec_task_manager_unittest_011, TestSize.Level1)
{
    sptr<AudioCapturerSession> session = new AudioCapturerSession();
    VideoCodecType type = VideoCodecType::VIDEO_ENCODE_TYPE_AVC;
    ColorSpace colorSpace = ColorSpace::DISPLAY_P3;
    sptr<AvcodecTaskManager> taskManager = new AvcodecTaskManager(session, type, colorSpace);

    taskManager->videoEncoder_ = make_shared<VideoEncoder>(type, colorSpace);
    taskManager->videoEncoder_->isStarted_ = true;
    taskManager->audioEncoder_ = nullptr;
    taskManager->audioDeferredProcess_ = nullptr;
    taskManager->timerId_ = 0;

    taskManager->Release();
    EXPECT_FALSE(taskManager->videoEncoder_->isStarted_);
    EXPECT_EQ(taskManager->audioEncoder_, nullptr);
    EXPECT_EQ(taskManager->audioDeferredProcess_, nullptr);
    EXPECT_EQ(taskManager->timerId_, 0);
}

/*
 * Feature: Framework
 * Function: Test Release abnormal branches when audioEncoder_ is not nullptr.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test Release abnormal branches when audioEncoder_ is not nullptr.
 */
HWTEST_F(AvcodecTaskManagerUnitTest, avcodec_task_manager_unittest_012, TestSize.Level1)
{
    sptr<AudioCapturerSession> session = new AudioCapturerSession();
    VideoCodecType type = VideoCodecType::VIDEO_ENCODE_TYPE_AVC;
    ColorSpace colorSpace = ColorSpace::DISPLAY_P3;
    sptr<AvcodecTaskManager> taskManager = new AvcodecTaskManager(session, type, colorSpace);

    taskManager->videoEncoder_ = nullptr;
    taskManager->audioEncoder_ = make_unique<AudioEncoder>();
    taskManager->audioEncoder_->encoder_ = nullptr;
    taskManager->audioEncoder_->isStarted_ = true;
    taskManager->audioDeferredProcess_ = nullptr;
    taskManager->timerId_ = 0;

    taskManager->Release();
    EXPECT_EQ(taskManager->videoEncoder_, nullptr);
    EXPECT_FALSE(taskManager->audioEncoder_->isStarted_);
    EXPECT_EQ(taskManager->audioDeferredProcess_, nullptr);
    EXPECT_EQ(taskManager->timerId_, 0);
}

/*
 * Feature: Framework
 * Function: Test FindIdrFrameIndex normal branches when find IDR frame.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test FindIdrFrameIndex normal branches when find IDR frame.
 */
HWTEST_F(AvcodecTaskManagerUnitTest, avcodec_task_manager_unittest_013, TestSize.Level1)
{
    sptr<AudioCapturerSession> session = new AudioCapturerSession();
    VideoCodecType type = VideoCodecType::VIDEO_ENCODE_TYPE_AVC;
    ColorSpace colorSpace = ColorSpace::DISPLAY_P3;
    sptr<AvcodecTaskManager> taskManager = new AvcodecTaskManager(session, type, colorSpace);

    vector<sptr<FrameRecord>> frameRecords;
    int64_t timestamp = VIDEO_FRAMERATE;
    GraphicTransformType graphicType = GRAPHIC_ROTATE_90;
    sptr<SurfaceBuffer> videoBuffer1 = SurfaceBuffer::Create();
    ASSERT_NE(videoBuffer1, nullptr);
    sptr<FrameRecord> frameRecord1 =
        new(std::nothrow) FrameRecord(videoBuffer1, timestamp, graphicType);
    ASSERT_NE(frameRecord1, nullptr);
    frameRecord1->SetIDRProperty(false);
    frameRecords.push_back(frameRecord1);

    sptr<SurfaceBuffer> videoBuffer2 = SurfaceBuffer::Create();
    ASSERT_NE(videoBuffer2, nullptr);
    sptr<FrameRecord> frameRecord2 =
        new(std::nothrow) FrameRecord(videoBuffer2, timestamp, graphicType);
    ASSERT_NE(frameRecord2, nullptr);
    frameRecord2->SetIDRProperty(true);
    frameRecord2->timestamp_ = 1;
    frameRecords.push_back(frameRecord2);

    taskManager->preBufferDuration_ = 0;
    int64_t shutterTime = 1;
    int32_t captureId = 1;
    int64_t clearVideoEndTime = shutterTime + taskManager->preBufferDuration_;
    size_t ret = taskManager->FindIdrFrameIndex(frameRecords, clearVideoEndTime, shutterTime, captureId);
    EXPECT_EQ(ret, 1);
}

/*
 * Feature: Framework
 * Function: Test FindIdrFrameIndex normal branches when find IDR frame and timestamp_ less than start time.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test FindIdrFrameIndex normal branches when find IDR frame and timestamp_ less than start time.
 */
HWTEST_F(AvcodecTaskManagerUnitTest, avcodec_task_manager_unittest_014, TestSize.Level1)
{
    sptr<AudioCapturerSession> session = new AudioCapturerSession();
    VideoCodecType type = VideoCodecType::VIDEO_ENCODE_TYPE_AVC;
    ColorSpace colorSpace = ColorSpace::DISPLAY_P3;
    sptr<AvcodecTaskManager> taskManager = new AvcodecTaskManager(session, type, colorSpace);

    vector<sptr<FrameRecord>> frameRecords;
    int64_t timestamp = VIDEO_FRAMERATE;
    GraphicTransformType graphicType = GRAPHIC_ROTATE_90;
    sptr<SurfaceBuffer> videoBuffer1 = SurfaceBuffer::Create();
    ASSERT_NE(videoBuffer1, nullptr);
    sptr<FrameRecord> frameRecord1 =
        new(std::nothrow) FrameRecord(videoBuffer1, timestamp, graphicType);
    ASSERT_NE(frameRecord1, nullptr);
    frameRecord1->SetIDRProperty(false);
    frameRecords.push_back(frameRecord1);

    sptr<SurfaceBuffer> videoBuffer2 = SurfaceBuffer::Create();
    ASSERT_NE(videoBuffer2, nullptr);
    sptr<FrameRecord> frameRecord2 =
        new(std::nothrow) FrameRecord(videoBuffer2, timestamp, graphicType);
    ASSERT_NE(frameRecord2, nullptr);
    frameRecord2->SetIDRProperty(true);
    frameRecord2->timestamp_ = 0;
    frameRecords.push_back(frameRecord2);

    taskManager->preBufferDuration_ = 0;
    int64_t shutterTime = 1;
    int32_t captureId = 1;
    int64_t clearVideoEndTime = shutterTime + taskManager->preBufferDuration_;
    size_t ret = taskManager->FindIdrFrameIndex(frameRecords, clearVideoEndTime, shutterTime, captureId);
    EXPECT_EQ(ret, 0);
}

/*
 * Feature: Framework
 * Function: Test FindIdrFrameIndex normal branches when not find IDR frame.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test FindIdrFrameIndex normal branches when not find IDR frame.
 */
HWTEST_F(AvcodecTaskManagerUnitTest, avcodec_task_manager_unittest_015, TestSize.Level1)
{
    sptr<AudioCapturerSession> session = new AudioCapturerSession();
    VideoCodecType type = VideoCodecType::VIDEO_ENCODE_TYPE_AVC;
    ColorSpace colorSpace = ColorSpace::DISPLAY_P3;
    sptr<AvcodecTaskManager> taskManager = new AvcodecTaskManager(session, type, colorSpace);

    vector<sptr<FrameRecord>> frameRecords;
    int64_t timestamp = VIDEO_FRAMERATE;
    GraphicTransformType graphicType = GRAPHIC_ROTATE_90;
    sptr<SurfaceBuffer> videoBuffer = SurfaceBuffer::Create();
    ASSERT_NE(videoBuffer, nullptr);
    sptr<FrameRecord> frameRecord =
        new(std::nothrow) FrameRecord(videoBuffer, timestamp, graphicType);
    ASSERT_NE(frameRecord, nullptr);
    frameRecord->SetIDRProperty(false);
    frameRecords.push_back(frameRecord);

    taskManager->preBufferDuration_ = 0;
    int64_t shutterTime = 1;
    int32_t captureId = 1;
    int64_t clearVideoEndTime = shutterTime + taskManager->preBufferDuration_;
    size_t ret = taskManager->FindIdrFrameIndex(frameRecords, clearVideoEndTime, shutterTime, captureId);
    EXPECT_EQ(ret, 0);
}

/*
 * Feature: Framework
 * Function: Test ChooseVideoBuffer abnormal branches.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test ChooseVideoBuffer abnormal branches.
 */
HWTEST_F(AvcodecTaskManagerUnitTest, avcodec_task_manager_unittest_016, TestSize.Level0)
{
    sptr<AudioCapturerSession> session = new AudioCapturerSession();
    VideoCodecType type = VideoCodecType::VIDEO_ENCODE_TYPE_AVC;
    ColorSpace colorSpace = ColorSpace::DISPLAY_P3;
    sptr<AvcodecTaskManager> taskManager = new AvcodecTaskManager(session, type, colorSpace);

    vector<sptr<FrameRecord>> frameRecords;
    sptr<SurfaceBuffer> videoBuffer1 = SurfaceBuffer::Create();
    int64_t timestamp1 = 0;
    GraphicTransformType types = GraphicTransformType::GRAPHIC_FLIP_H_ROT90;
    sptr<FrameRecord> frame1 = new FrameRecord(videoBuffer1, timestamp1, types);
    frame1->SetIDRProperty(true);
    frameRecords.emplace_back(frame1);
    sptr<SurfaceBuffer> videoBuffer2 = SurfaceBuffer::Create();
    int64_t timestamp2 = 3200000001LL;
    sptr<FrameRecord> frame2 = new FrameRecord(videoBuffer2, timestamp2, types);
    frame2->SetIDRProperty(false);
    vector<sptr<FrameRecord>> choosedBuffer;
    int64_t shutterTime = 1600000000LL;
    int32_t captureId = 1;
    taskManager->ChooseVideoBuffer(frameRecords, choosedBuffer, shutterTime, captureId);
    EXPECT_EQ(choosedBuffer.size(), 1);
}

} // CameraStandard
} // OHOS
