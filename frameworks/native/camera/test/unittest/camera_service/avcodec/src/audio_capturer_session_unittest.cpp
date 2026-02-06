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

#include "audio_capturer_session_unittest.h"

#include "audio_capturer_session.h"
#include "camera_dynamic_loader.h"
#include "camera_log.h"
#include "capture_scene_const.h"
#include "ipc_skeleton.h"
#include "avcodec_task_manager.h"
#include "test_token.h"

using namespace testing::ext;

namespace OHOS {
namespace CameraStandard {

void AudioCapturerSessionUnitTest::SetUpTestCase(void)
{
    MEDIA_DEBUG_LOG("AudioCapturerSessionUnitTest::SetUpTestCase started!");
    ASSERT_TRUE(TestToken().GetAllCameraPermission());
}

void AudioCapturerSessionUnitTest::TearDownTestCase(void)
{
    MEDIA_DEBUG_LOG("AudioCapturerSessionUnitTest::TearDownTestCase started!");
}

void AudioCapturerSessionUnitTest::SetUp()
{
    MEDIA_DEBUG_LOG("AudioCapturerSessionUnitTest::SetUp started!");
}

void AudioCapturerSessionUnitTest::TearDown()
{
    MEDIA_DEBUG_LOG("AudioCapturerSessionUnitTest::TearDown started!");
}

/*
 * Feature: Framework
 * Function: Test GetAudioRecords normal branches.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetAudioRecords normal branches.
 */
HWTEST_F(AudioCapturerSessionUnitTest, audio_capturer_session_unittest_001, TestSize.Level0)
{
    int64_t startTime = 1;
    int64_t endTime = 10;
    vector<sptr<AudioRecord>> audioRecords;
    sptr<AudioCapturerSession> session = new AudioCapturerSession();
    session->GetAudioRecords(startTime, endTime, audioRecords);
    EXPECT_TRUE(audioRecords.empty());
}

/*
 * Feature: Framework
 * Function: Test CreateAudioCapturer
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CreateAudioCapturer normal branches.
 */
HWTEST_F(AudioCapturerSessionUnitTest, audio_capturer_session_unittest_002, TestSize.Level1)
{
    sptr<AudioCapturerSession> session = new AudioCapturerSession();
    bool ret = session->CreateAudioCapturer();
    std::shared_ptr<AudioCapturer> audioCapturer = session->GetAudioCapturer();
    ASSERT_NE(audioCapturer, nullptr);
    EXPECT_TRUE(ret);
    session->ProcessAudioBuffer();
    session->Stop();
}

/*
 * Feature: Framework
 * Function: Test SetStopAudioRecord
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetStopAudioRecord normal branches.
 */
HWTEST_F(AudioCapturerSessionUnitTest, audio_capturer_session_unittest_003, TestSize.Level1)
{
    sptr<AudioCapturerSession> audioCaptureSession = new AudioCapturerSession();
    sptr<AudioTaskManager> audioTaskManager = new AudioTaskManager(audioCaptureSession);
    int32_t bufferLen = 32;
    sptr<AudioRecord> audioRecord = new AudioRecord(1000);
    auto buffer = new uint8_t[bufferLen];
    audioRecord->SetAudioBuffer(buffer, bufferLen);
    audioTaskManager->arrivalAudioBufferQueue_.Push(audioRecord);
    audioCaptureSession->SetStopAudioRecord();
    EXPECT_EQ(audioTaskManager->arrivalAudioBufferQueue_.Size(), 1);
}

/*
 * Feature: Framework
 * Function: Test SetStopAudioRecord
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetStopAudioRecord normal branches.
 */
HWTEST_F(AudioCapturerSessionUnitTest, audio_capturer_session_unittest_004, TestSize.Level1)
{
    sptr<AudioCapturerSession> audioCaptureSession = new AudioCapturerSession();
    sptr<AudioTaskManager> audioTaskManager = new AudioTaskManager(audioCaptureSession);
    int32_t bufferLen = 32;
    sptr<AudioRecord> audioRecord = new AudioRecord(1000);
    auto buffer = new uint8_t[bufferLen];
    audioRecord->SetAudioBuffer(buffer, bufferLen);
    audioTaskManager->arrivalAudioBufferQueue_.Push(audioRecord);
    audioCaptureSession->SetStopAudioRecord();
    EXPECT_EQ(audioTaskManager->arrivalAudioBufferQueue_.Size(), 1);
}

/*
 * Feature: Framework
 * Function: Test SetStopAudioRecord
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetStopAudioRecord normal branches.
 */
HWTEST_F(AudioCapturerSessionUnitTest, audio_capturer_session_unittest_005, TestSize.Level1)
{
    sptr<AudioCapturerSession> session = new AudioCapturerSession();
    bool ret = session->CreateAudioCapturer();
    std::shared_ptr<AudioCapturer> audioCapturer = session->GetAudioCapturer();
    ASSERT_NE(audioCapturer, nullptr);
    EXPECT_TRUE(ret);
    sptr<AudioTaskManager> audioTaskManager = new AudioTaskManager(session);
    int32_t bufferLen = 32;
    sptr<AudioRecord> audioRecord = new AudioRecord(1000);
    auto buffer = new uint8_t[bufferLen];
    audioRecord->SetAudioBuffer(buffer, bufferLen);
    audioTaskManager->arrivalAudioBufferQueue_.Push(audioRecord);
    audioTaskManager->RegisterAudioBuffeArrivalCallback(100);
    EXPECT_FALSE(session->GetProcessedCbFunc());
    session->Release();
    EXPECT_EQ(session->audioCapturer_, nullptr);
    EXPECT_EQ(audioTaskManager->arrivalAudioBufferQueue_.Size(), 0);
    EXPECT_TRUE(session->GetProcessedCbFunc());
}

} // CameraStandard
} // OHOS
