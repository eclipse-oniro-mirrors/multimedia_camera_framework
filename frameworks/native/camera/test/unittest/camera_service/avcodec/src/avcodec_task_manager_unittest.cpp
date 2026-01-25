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
HWTEST_F(AvcodecTaskManagerUnitTest, avcodec_task_manager_unittest_001, TestSize.Level0)
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
HWTEST_F(AvcodecTaskManagerUnitTest, avcodec_task_manager_unittest_002, TestSize.Level0)
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
HWTEST_F(AvcodecTaskManagerUnitTest, avcodec_task_manager_unittest_003, TestSize.Level0)
{
    sptr<AudioCapturerSession> session = new AudioCapturerSession();
    VideoCodecType type = VideoCodecType::VIDEO_ENCODE_TYPE_AVC;
    ColorSpace colorSpace = ColorSpace::DISPLAY_P3;
    sptr<AvcodecTaskManager> taskManager = new AvcodecTaskManager(session, type, colorSpace);

    vector<sptr<FrameRecord>> frameRecords;
    vector<sptr<FrameRecord>> choosedBuffer;
    int64_t shutterTime = 1;
    int32_t captureId = 1;
    int64_t timeStamp = 0;
    taskManager->ChooseVideoBuffer(frameRecords, choosedBuffer, shutterTime, captureId, timeStamp);
    EXPECT_EQ(choosedBuffer.size(), 0);
    vector<sptr<FrameRecord>> frameRecordVec;
    
    int64_t timestamp1 = 1000;
    sptr<SurfaceBuffer> surfaceBuffer1 = SurfaceBuffer::Create();
    GraphicTransformType type1 = GRAPHIC_ROTATE_90;
    sptr<FrameRecord> frameRecord1 = new FrameRecord(surfaceBuffer1, timestamp1, type1);
    ASSERT_NE(frameRecord1, nullptr);
    frameRecordVec.push_back(frameRecord1);
    
    int64_t timestamp2 = 2000;
    sptr<SurfaceBuffer> surfaceBuffer2 = SurfaceBuffer::Create();
    GraphicTransformType type2 = GRAPHIC_ROTATE_90;
    sptr<FrameRecord> frameRecord2 = new FrameRecord(surfaceBuffer2, timestamp2, type2);
    ASSERT_NE(frameRecord2, nullptr);
    frameRecordVec.push_back(frameRecord2);
    
    sptr<AudioVideoMuxer> muxer;
    taskManager->CollectAudioBuffer(frameRecordVec, muxer, true);
    EXPECT_EQ(frameRecordVec.size(), 2);
}

/*
 * Feature: Framework
 * Function: Test Stop abnormal branches while videoEncoder_ is nullptr.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test Stop abnormal branches while videoEncoder_ is nullptr.
 */
HWTEST_F(AvcodecTaskManagerUnitTest, avcodec_task_manager_unittest_004, TestSize.Level0)
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
HWTEST_F(AvcodecTaskManagerUnitTest, avcodec_task_manager_unittest_005, TestSize.Level0)
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
    
    taskManager->Release();
    EXPECT_EQ(taskManager->audioEncoder_, nullptr);
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

    taskManager->Release();
    EXPECT_EQ(taskManager->videoEncoder_, nullptr);
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
    EXPECT_EQ(ret, 0);
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
    int64_t timeStamp;
    taskManager->ChooseVideoBuffer(frameRecords, choosedBuffer, shutterTime, captureId, timeStamp);
    EXPECT_EQ(choosedBuffer.size(), 1);
}

/*
 * Feature: Framework
 * Function: Test ProcessAudioBuffer for once record.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test ProcessAudioBuffer for once record.
 */
HWTEST_F(AvcodecTaskManagerUnitTest, avcodec_task_manager_unittest_017, TestSize.Level0)
{
    sptr<AudioCapturerSession> audioCaptureSession = new AudioCapturerSession();
    sptr<AudioTaskManager> audioTaskManager = new AudioTaskManager(audioCaptureSession);
    int32_t captureId = 1;
    int64_t timeStamp = 1000;
    audioTaskManager->ProcessAudioBuffer(captureId, timeStamp);
    EXPECT_EQ(audioTaskManager->curCaptureIdToTimeMap_.size(), 1);
    bool isCbFuncNull = audioCaptureSession->GetProcessedCbFunc();
    EXPECT_EQ(isCbFuncNull, 0);
}

/*
 * Feature: Framework
 * Function: Test AudioTaskManager OnAudioBufferArrival for once audioBuffer return.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test AudioTaskManager OnAudioBufferArrival for once audioBuffer return.
 */
HWTEST_F(AvcodecTaskManagerUnitTest, avcodec_task_manager_unittest_018, TestSize.Level0)
{
    sptr<AudioCapturerSession> audioCaptureSession = new AudioCapturerSession();
    sptr<AudioTaskManager> audioTaskManager = new AudioTaskManager(audioCaptureSession);
    sptr<AudioRecord> audioRecord = new AudioRecord(1);
    int32_t bufferLen = 32;
    auto buffer = new uint8_t[bufferLen];
    audioRecord->SetAudioBuffer(buffer, bufferLen);
    audioTaskManager->OnAudioBufferArrival(audioRecord, false);
    EXPECT_EQ(audioTaskManager->arrivalAudioBufferQueue_.Size(), 1);
}

/*
 * Feature: Framework
 * Function: Test AudioTaskManager OnAudioBufferArrival for process normal branches.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test AudioTaskManager OnAudioBufferArrival for process normal branches.
 */
HWTEST_F(AvcodecTaskManagerUnitTest, avcodec_task_manager_unittest_019, TestSize.Level0)
{
    sptr<AudioCapturerSession> audioCaptureSession = new AudioCapturerSession();
    sptr<AudioTaskManager> audioTaskManager = new AudioTaskManager(audioCaptureSession);
    int32_t bufferLen = 32;
    sptr<AudioRecord> audioRecord1 = new AudioRecord(1);
    auto audioBuffer1 = new uint8_t[bufferLen];
    audioRecord1->SetAudioBuffer(audioBuffer1, bufferLen);
    audioTaskManager->arrivalAudioBufferQueue_.Push(audioRecord1);
    sptr<AudioRecord> audioRecord2 = new AudioRecord(2);
    auto audioBuffer2 = new uint8_t[bufferLen];
    audioRecord2->SetAudioBuffer(audioBuffer2, bufferLen);
    audioTaskManager->arrivalAudioBufferQueue_.Push(audioRecord2);
    sptr<AudioRecord> audioRecord3 = new AudioRecord(3);
    auto audioBuffer3 = new uint8_t[bufferLen];
    audioRecord3->SetAudioBuffer(audioBuffer3, bufferLen);
    audioTaskManager->arrivalAudioBufferQueue_.Push(audioRecord3);
    sptr<AudioRecord> audioRecord4 = new AudioRecord(4);
    auto audioBuffer4 = new uint8_t[bufferLen];
    audioRecord4->SetAudioBuffer(audioBuffer4, bufferLen);
    audioTaskManager->arrivalAudioBufferQueue_.Push(audioRecord4);
    EXPECT_EQ(audioTaskManager->arrivalAudioBufferQueue_.Size(), 4);
    audioTaskManager->SetIsBufferArrivalFinished(true);
    sptr<AudioRecord> audioRecord5 = new AudioRecord(5);
    auto audioBuffer5 = new uint8_t[bufferLen];
    audioRecord4->SetAudioBuffer(audioBuffer5, bufferLen);
    audioTaskManager->OnAudioBufferArrival(audioRecord5, true);
    EXPECT_EQ(audioTaskManager->processedAudioRecordCache_.size(), 0);
    EXPECT_EQ(audioTaskManager->arrivalAudioBufferQueue_.Size(), 5);
}

/*
 * Feature: Framework
 * Function: Test AudioTaskManager OnAudioBufferArrival for process abnormal branches.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test AudioTaskManager OnAudioBufferArrival for process abnormal branches.
 */
HWTEST_F(AvcodecTaskManagerUnitTest, avcodec_task_manager_unittest_020, TestSize.Level0)
{
    sptr<AudioCapturerSession> audioCaptureSession = new AudioCapturerSession();
    sptr<AudioTaskManager> audioTaskManager = new AudioTaskManager(audioCaptureSession);
    int32_t bufferLen = 32;
    sptr<AudioRecord> audioRecord1 = new AudioRecord(1);
    auto audioBuffer1 = new uint8_t[bufferLen];
    audioRecord1->SetAudioBuffer(audioBuffer1, bufferLen);
    audioTaskManager->arrivalAudioBufferQueue_.Push(audioRecord1);
    sptr<AudioRecord> audioRecord2 = new AudioRecord(2);
    auto audioBuffer2 = new uint8_t[bufferLen];
    audioRecord2->SetAudioBuffer(audioBuffer2, bufferLen);
    audioTaskManager->arrivalAudioBufferQueue_.Push(audioRecord2);
    sptr<AudioRecord> audioRecord3 = new AudioRecord(3);
    auto audioBuffer3 = new uint8_t[bufferLen];
    audioRecord3->SetAudioBuffer(audioBuffer3, bufferLen);
    audioTaskManager->arrivalAudioBufferQueue_.Push(audioRecord3);
    sptr<AudioRecord> audioRecord4 = new AudioRecord(4);
    auto audioBuffer4 = new uint8_t[bufferLen];
    audioRecord4->SetAudioBuffer(audioBuffer4, bufferLen);
    audioTaskManager->arrivalAudioBufferQueue_.Push(audioRecord4);
    EXPECT_EQ(audioTaskManager->arrivalAudioBufferQueue_.Size(), 4);
    audioTaskManager->SetIsBufferArrivalFinished(false);
    sptr<AudioRecord> audioRecord5 = new AudioRecord(5);
    auto audioBuffer5 = new uint8_t[bufferLen];
    audioRecord4->SetAudioBuffer(audioBuffer5, bufferLen);
    audioTaskManager->OnAudioBufferArrival(audioRecord5, true);
    EXPECT_EQ(audioTaskManager->processedAudioRecordCache_.size(), 0);
    EXPECT_EQ(audioTaskManager->arrivalAudioBufferQueue_.Size(), 5);
}

/*
 * Feature: Framework
 * Function: Test AudioTaskManager OnAudioBufferArrival for process abnormal branches.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test AudioTaskManager OnAudioBufferArrival for process abnormal branches.
 */
HWTEST_F(AvcodecTaskManagerUnitTest, avcodec_task_manager_unittest_021, TestSize.Level0)
{
    sptr<AudioCapturerSession> audioCaptureSession = new AudioCapturerSession();
    sptr<AudioTaskManager> audioTaskManager = new AudioTaskManager(audioCaptureSession);
    int32_t bufferLen = 32;
    sptr<AudioRecord> audioRecord1 = new AudioRecord(1000);
    auto audioBuffer1 = new uint8_t[bufferLen];
    audioRecord1->SetAudioBuffer(audioBuffer1, bufferLen);
    audioTaskManager->arrivalAudioBufferQueue_.Push(audioRecord1);
    EXPECT_EQ(audioTaskManager->arrivalAudioBufferQueue_.Size(), 1);
    audioTaskManager->RegisterAudioBuffeArrivalCallback(1002);
    EXPECT_EQ(audioCaptureSession->GetProcessedCbFunc(), false);
    sptr<AudioRecord> audioRecord2 = new AudioRecord(1001);
    auto audioBuffer2 = new uint8_t[bufferLen];
    audioRecord2->SetAudioBuffer(audioBuffer2, bufferLen);
    audioCaptureSession->processCallback_(audioRecord2, true);
    EXPECT_EQ(audioTaskManager->arrivalAudioBufferQueue_.Size(), 0);
}

/*
 * Feature: Framework
 * Function: Test normal branches for AudioTaskManager RegisterAudioBuffeArrivalCallback.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test normal branches for AudioTaskManager RegisterAudioBuffeArrivalCallback.
 */
HWTEST_F(AvcodecTaskManagerUnitTest, avcodec_task_manager_unittest_022, TestSize.Level0)
{
    sptr<AudioCapturerSession> audioCaptureSession = new AudioCapturerSession();
    sptr<AudioTaskManager> audioTaskManager = new AudioTaskManager(audioCaptureSession);
    audioTaskManager->RegisterAudioBuffeArrivalCallback(1000);
    EXPECT_EQ(audioCaptureSession->GetProcessedCbFunc(), false);
    sptr<AudioRecord> audioRecord = new AudioRecord(1001);
    int32_t bufferLen = 32;
    auto buffer = new uint8_t[bufferLen];
    audioRecord->SetAudioBuffer(buffer, bufferLen);
    audioCaptureSession->processCallback_(audioRecord, false);
    EXPECT_EQ(audioTaskManager->arrivalAudioBufferQueue_.Size(), 1);
}

/*
 * Feature: Framework
 * Function: Test Release normal branches when AudioBufferQueue_ is not nullptr.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test Release normal branches when AudioBufferQueue_ is not nullptr.
 */
HWTEST_F(AvcodecTaskManagerUnitTest, avcodec_task_manager_unittest_023, TestSize.Level0)
{
    sptr<AudioCapturerSession> audioCaptureSession = new AudioCapturerSession();
    sptr<AudioTaskManager> audioTaskManager = new AudioTaskManager(audioCaptureSession);
    int32_t bufferLen = 32;
    sptr<AudioRecord> audioRecord = new AudioRecord(1001);
    auto buffer = new uint8_t[bufferLen];
    audioRecord->SetAudioBuffer(buffer, bufferLen);
    audioTaskManager->arrivalAudioBufferQueue_.Push(audioRecord);
    sptr<AudioRecord> audioRecord1 = new AudioRecord(1001);
    auto buffer1 = new uint8_t[bufferLen];
    audioRecord1->SetAudioBuffer(buffer1, bufferLen);
    audioTaskManager->processedAudioRecordCache_.emplace_back(audioRecord1);
    audioTaskManager->timerId_ = 0;
    audioTaskManager->curCaptureIdToTimeMap_[1] = 100;

    audioTaskManager->Release();
    EXPECT_EQ(audioTaskManager->processedAudioRecordCache_.size(), 0);
    EXPECT_EQ(audioTaskManager->arrivalAudioBufferQueue_.Size(), 0);
    EXPECT_EQ(audioTaskManager->timerId_, 0);
    EXPECT_EQ(audioTaskManager->curCaptureIdToTimeMap_.size(), 0);
}

/*
 * Feature: Framework
 * Function: Test normal branches for AudioTaskManager PrepareAudioBuffer.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test normal branches for AudioTaskManager PrepareAudioBuffer.
 */
HWTEST_F(AvcodecTaskManagerUnitTest, avcodec_task_manager_unittest_024, TestSize.Level0)
{
    sptr<AudioCapturerSession> audioCaptureSession = new AudioCapturerSession();
    sptr<AudioTaskManager> audioTaskManager = new AudioTaskManager(audioCaptureSession);
    int32_t bufferLen = 32;
    sptr<AudioRecord> audioRecord1 = new AudioRecord(99);
    auto audioBuffer1 = new uint8_t[bufferLen];
    audioRecord1->SetAudioBuffer(audioBuffer1, bufferLen);
    audioCaptureSession->audioBufferQueue_.Push(audioRecord1);
    sptr<AudioRecord> audioRecord2 = new AudioRecord(200);
    auto audioBuffer2 = new uint8_t[bufferLen];
    audioRecord2->SetAudioBuffer(audioBuffer2, bufferLen);
    audioCaptureSession->audioBufferQueue_.Push(audioRecord2);
    audioTaskManager->PrepareAudioBuffer(100000000);
    EXPECT_EQ(audioTaskManager->arrivalAudioBufferQueue_.Size(), 1);
}

/*
 * Feature: Framework
 * Function: Test AudioTaskManager GetAudioTaskManager and GetAudioProcessManager normal branches.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test AudioTaskManager GetAudioTaskManager and GetAudioProcessManager normal branches.
 */
HWTEST_F(AvcodecTaskManagerUnitTest, avcodec_task_manager_unittest_025, TestSize.Level0)
{
    sptr<AudioCapturerSession> audioCaptureSession = new AudioCapturerSession();
    sptr<AudioTaskManager> audioTaskManager = new AudioTaskManager(audioCaptureSession);
    shared_ptr<TaskManager> manager = audioTaskManager->GetAudioTaskManager();
    ASSERT_NE(manager, nullptr);
    audioTaskManager->audioProcessTaskManager_ = make_unique<TaskManager>("AudioTaskManager",
        DEFAULT_AUDIO_TASK_THREAD_NUMBER, false);
    manager = audioTaskManager->GetAudioTaskManager();
    ASSERT_NE(manager, nullptr);

    manager = audioTaskManager->GetAudioProcessManager();
    ASSERT_NE(manager, nullptr);
    audioTaskManager->audioRecordProcessManager_ = make_unique<TaskManager>("AudioProcessTaskManager",
        DEFAULT_PROCESSED_THREAD_NUMBER, false);
    manager = audioTaskManager->GetAudioProcessManager();
    ASSERT_NE(manager, nullptr);
    audioTaskManager->SubmitTask(MyFunction);
}

/*
 * Feature: Framework
 * Function: Test AvcodecTaskManager WaitForAudioRecordFinished abnormal branches.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test AvcodecTaskManager WaitForAudioRecordFinished abnormal branches.
 */
HWTEST_F(AvcodecTaskManagerUnitTest, avcodec_task_manager_unittest_026, TestSize.Level0)
{
    sptr<AudioCapturerSession> session = new AudioCapturerSession();
    VideoCodecType type = VideoCodecType::VIDEO_ENCODE_TYPE_AVC;
    ColorSpace colorSpace = ColorSpace::DISPLAY_P3;
    sptr<AvcodecTaskManager> taskManager = new AvcodecTaskManager(session, type, colorSpace);

    vector<sptr<FrameRecord>> choosedBuffer;
    taskManager->WaitForAudioRecordFinished(choosedBuffer);
    EXPECT_TRUE(choosedBuffer.empty());
}

/*
 * Feature: Framework
 * Function: Test AvcodecTaskManager CollectAudioBuffer abnormal branches.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test AvcodecTaskManager CollectAudioBuffer abnormal branches.
 */
HWTEST_F(AvcodecTaskManagerUnitTest, avcodec_task_manager_unittest_027, TestSize.Level0)
{
    sptr<AudioCapturerSession> session = new AudioCapturerSession();
    VideoCodecType type = VideoCodecType::VIDEO_ENCODE_TYPE_AVC;
    ColorSpace colorSpace = ColorSpace::DISPLAY_P3;
    sptr<AvcodecTaskManager> taskManager = new AvcodecTaskManager(session, type, colorSpace);
    sptr<AudioCapturerSession> audioCaptureSession = new AudioCapturerSession();
    sptr<AudioTaskManager> audioTaskManager = new AudioTaskManager(audioCaptureSession);
    audioTaskManager->processedAudioRecordCache_.clear();
    EXPECT_TRUE(audioTaskManager->processedAudioRecordCache_.empty());

    vector<sptr<FrameRecord>> choosedBuffer;
    EXPECT_EQ(choosedBuffer.size(), 0);
    sptr<AudioVideoMuxer> muxer;
    taskManager->CollectAudioBuffer(choosedBuffer, muxer, true);
    EXPECT_EQ(choosedBuffer.size(), 0);
}
} // CameraStandard
} // OHOS