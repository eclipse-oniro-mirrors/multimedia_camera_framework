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

#include "audio_deferred_process_unittest.h"

#include "audio_deferred_process.h"
#include "camera_log.h"

using namespace testing::ext;

namespace OHOS {
namespace CameraStandard {

void AudioDeferredProcessUnitTest::SetUpTestCase(void)
{
    MEDIA_DEBUG_LOG("AudioDeferredProcessUnitTest::SetUpTestCase started!");
}

void AudioDeferredProcessUnitTest::TearDownTestCase(void)
{
    MEDIA_DEBUG_LOG("AudioDeferredProcessUnitTest::TearDownTestCase started!");
}

void AudioDeferredProcessUnitTest::SetUp()
{
    MEDIA_DEBUG_LOG("AudioDeferredProcessUnitTest::SetUp started!");
}

void AudioDeferredProcessUnitTest::TearDown()
{
    MEDIA_DEBUG_LOG("AudioDeferredProcessUnitTest::TearDown started!");
}

/*
 * Feature: Framework
 * Function: Test offlineAudioEffectChain.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test offlineAudioEffectChain normal branches.
 */
HWTEST_F(AudioDeferredProcessUnitTest, audio_deferred_process_unittest_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("audio_deferred_process_unittest_001 Start");
    sptr<AudioDeferredProcess> process = new AudioDeferredProcess();
    ASSERT_NE(process, nullptr);
    process->GetOfflineEffectChain();
    ASSERT_NE(process->offlineAudioEffectManager_, nullptr);
    AudioStreamInfo inputOptions;
    inputOptions.samplingRate = AudioSamplingRate::SAMPLE_RATE_8000;
    inputOptions.channels = AudioChannel::MONO;
    AudioStreamInfo outputOptions;
    outputOptions.samplingRate = AudioSamplingRate::SAMPLE_RATE_8000;
    inputOptions.channels = AudioChannel::CHANNEL_UNKNOW;
    process->StoreOptions(inputOptions, outputOptions);
    process->Release();
    ASSERT_EQ(process->offlineAudioEffectManager_, nullptr);
    ASSERT_EQ(process->offlineEffectChain_, nullptr);
    MEDIA_INFO_LOG("audio_deferred_process_unittest_001 End");
}

/*
 * Feature: Framework
 * Function: Test Process
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test Process abnormal branches.
 */
HWTEST_F(AudioDeferredProcessUnitTest, audio_deferred_process_unittest_002, TestSize.Level1)
{
    MEDIA_INFO_LOG("audio_deferred_process_unittest_002 Start");
    sptr<AudioDeferredProcess> process = new AudioDeferredProcess();
    ASSERT_NE(process, nullptr);
    process->chainName_ = "test";
    process->GetOfflineEffectChain();
    ASSERT_NE(process->offlineAudioEffectManager_, nullptr);
    std::vector<sptr<AudioRecord>> audioRecords;
    sptr<AudioRecord> record1 = new AudioRecord(1);
    sptr<AudioRecord> record2 = new AudioRecord(2);
    audioRecords.push_back(record1);
    audioRecords.push_back(record2);
    std::vector<sptr<AudioRecord>> processedRecords;
    int32_t ret = process->Process(audioRecords, processedRecords);
    EXPECT_EQ(ret, -1);
    process->Release();
    MEDIA_INFO_LOG("audio_deferred_process_unittest_002 End");
}

} // CameraStandard
} // OHOS
