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
    sptr<AvcodecTaskManager> taskManager = new AvcodecTaskManager(session, type);

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
    sptr<AvcodecTaskManager> taskManager = new AvcodecTaskManager(session, type);

    vector<sptr<FrameRecord>> frameRecords;
    uint64_t taskName = 1;
    int32_t captureRotation = 1;
    int32_t captureId = 1;
    taskManager->DoMuxerVideo(frameRecords, taskName, captureRotation, captureId);
    EXPECT_TRUE(frameRecords.empty());
}

/*
 * Feature: Framework
 * Function: Test CollectAudioBuffer normal branches.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CollectAudioBuffer normal branches.
 */
HWTEST_F(AvcodecTaskManagerUnitTest, avcodec_task_manager_unittest_003, TestSize.Level0)
{
    sptr<AudioCapturerSession> session = new AudioCapturerSession();
    VideoCodecType type = VideoCodecType::VIDEO_ENCODE_TYPE_AVC;
    sptr<AvcodecTaskManager> taskManager = new AvcodecTaskManager(session, type);

    vector<sptr<FrameRecord>> frameRecords;
    vector<sptr<FrameRecord>> choosedBuffer;
    int64_t shutterTime = 1;
    int32_t captureId = 1;
    taskManager->ChooseVideoBuffer(frameRecords, choosedBuffer, shutterTime, captureId);
    vector<sptr<AudioRecord>> audioRecordVec;
    sptr<AudioVideoMuxer> muxer;
    taskManager->CollectAudioBuffer(audioRecordVec, muxer);
}

/*
 * Feature: Framework
 * Function: Test Release abnormal branches while videoEncoder_ is nullptr.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test Release abnormal branches while videoEncoder_ is nullptr.
 */
HWTEST_F(AvcodecTaskManagerUnitTest, avcodec_task_manager_unittest_004, TestSize.Level0)
{
    sptr<AudioCapturerSession> session = new AudioCapturerSession();
    VideoCodecType type = VideoCodecType::VIDEO_ENCODE_TYPE_AVC;
    sptr<AvcodecTaskManager> taskManager = new AvcodecTaskManager(session, type);

    taskManager->videoEncoder_ = nullptr;
    taskManager->audioEncoder_ = make_unique<AudioEncoder>();
}

/*
 * Feature: Framework
 * Function: Test Release abnormal branches while audioEncoder_ is nullptr.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test Release abnormal branches while audioEncoder_ is nullptr.
 */
HWTEST_F(AvcodecTaskManagerUnitTest, avcodec_task_manager_unittest_005, TestSize.Level0)
{
    sptr<AudioCapturerSession> session = new AudioCapturerSession();
    VideoCodecType type = VideoCodecType::VIDEO_ENCODE_TYPE_AVC;
    sptr<AvcodecTaskManager> taskManager = new AvcodecTaskManager(session, type);

    taskManager->videoEncoder_ = make_unique<VideoEncoder>(type);
    taskManager->audioEncoder_ = nullptr;
}

/*
 * Feature: Framework
 * Function: Test Stop abnormal branches while videoEncoder_ is nullptr.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test Stop abnormal branches while videoEncoder_ is nullptr.
 */
HWTEST_F(AvcodecTaskManagerUnitTest, avcodec_task_manager_unittest_006, TestSize.Level0)
{
    sptr<AudioCapturerSession> session = new AudioCapturerSession();
    VideoCodecType type = VideoCodecType::VIDEO_ENCODE_TYPE_AVC;
    sptr<AvcodecTaskManager> taskManager = new AvcodecTaskManager(session, type);

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
HWTEST_F(AvcodecTaskManagerUnitTest, avcodec_task_manager_unittest_007, TestSize.Level0)
{
    sptr<AudioCapturerSession> session = new AudioCapturerSession();
    VideoCodecType type = VideoCodecType::VIDEO_ENCODE_TYPE_AVC;
    sptr<AvcodecTaskManager> taskManager = new AvcodecTaskManager(session, type);

    taskManager->videoEncoder_ = make_unique<VideoEncoder>(type);
    taskManager->audioEncoder_ = nullptr;
    taskManager->Stop();
    EXPECT_FALSE(taskManager->videoEncoder_->isStarted_);
}
} // CameraStandard
} // OHOS
