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

using namespace testing::ext;

namespace OHOS {
namespace CameraStandard {

void AudioCapturerSessionUnitTest::SetUpTestCase(void)
{
    MEDIA_DEBUG_LOG("AudioCapturerSessionUnitTest::SetUpTestCase started!");
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
} // CameraStandard
} // OHOS
