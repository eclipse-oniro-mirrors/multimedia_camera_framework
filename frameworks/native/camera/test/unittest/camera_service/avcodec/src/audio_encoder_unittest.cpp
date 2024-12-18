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

#include "audio_encoder_unittest.h"

#include "audio_encoder.h"
#include "camera_dynamic_loader.h"
#include "camera_log.h"
#include "capture_scene_const.h"
#include "ipc_skeleton.h"
#include "external_window.h"
#include "native_avbuffer.h"
#include "native_avcodec_base.h"
#include "native_avcodec_videoencoder.h"
#include "sample_callback.h"

using namespace testing::ext;

namespace OHOS {
namespace CameraStandard {

void AudioEncoderUnitTest::SetUpTestCase(void)
{
    MEDIA_DEBUG_LOG("AudioEncoderUnitTest::SetUpTestCase started!");
}

void AudioEncoderUnitTest::TearDownTestCase(void)
{
    MEDIA_DEBUG_LOG("AudioEncoderUnitTest::TearDownTestCase started!");
}

void AudioEncoderUnitTest::SetUp()
{
    MEDIA_DEBUG_LOG("AudioEncoderUnitTest::SetUp started!");
}

void AudioEncoderUnitTest::TearDown()
{
    MEDIA_DEBUG_LOG("AudioEncoderUnitTest::TearDown started!");
}

/*
 * Feature: Framework
 * Function: Test EncodeAudioBuffer and Release normal branches.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test EncodeAudioBuffer and Release normal branches.
 */
HWTEST_F(AudioEncoderUnitTest, audio_encoder_unittest_001, TestSize.Level0)
{
    vector<sptr<AudioRecord>> audioRecords;
    std::string codecMime = "OH_AVCODEC_MIMETYPE_AUDIO_AAC";
    std::shared_ptr<AudioEncoder> coder = std::make_shared<AudioEncoder>();
    int32_t ret = coder->Create(codecMime);
    EXPECT_EQ(ret, 1);
    ret = coder->Config();
    EXPECT_EQ(ret, 1);
    ret = coder->Start();
    EXPECT_EQ(ret, 1);
    bool boolRet = coder->EncodeAudioBuffer(audioRecords);
    EXPECT_TRUE(boolRet);
    ret = coder->Stop();
    EXPECT_EQ(ret, 0);
    coder->encoder_ = nullptr;
}

/*
 * Feature: Framework
 * Function: Test EncodeAudioBuffer normal branches.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test EncodeAudioBuffer normal branches.
 */
HWTEST_F(AudioEncoderUnitTest, audio_encoder_unittest_002, TestSize.Level0)
{
    sptr<AudioRecord> audioRecord;
    std::string codecMime = "OH_AVCODEC_MIMETYPE_AUDIO_AAC";
    std::shared_ptr<AudioEncoder> coder = std::make_shared<AudioEncoder>();
    int32_t ret = coder->Create(codecMime);
    EXPECT_EQ(ret, 1);
    ret = coder->Config();
    EXPECT_EQ(ret, 1);
    ret = coder->Start();
    EXPECT_EQ(ret, 1);
    bool boolRet = coder->EncodeAudioBuffer(audioRecord);
    EXPECT_FALSE(boolRet);
    ret = coder->Stop();
    EXPECT_EQ(ret, 1);
}

/*
 * Feature: Framework
 * Function: Test EncodeAudioBuffer normal branches.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test EncodeAudioBuffer normal branches.
 */
HWTEST_F(AudioEncoderUnitTest, audio_encoder_unittest_003, TestSize.Level0)
{
    sptr<AudioRecord> audioRecord;
    std::string codecMime = "OH_AVCODEC_MIMETYPE_AUDIO_AAC";
    std::shared_ptr<AudioEncoder> coder = std::make_shared<AudioEncoder>();
    int32_t ret = coder->Create(codecMime);
    EXPECT_EQ(ret, 1);
    ret = coder->Config();
    EXPECT_EQ(ret, 1);
    ret = coder->Start();
    EXPECT_EQ(ret, 1);
    coder->encoder_ = nullptr;
    bool boolRet = coder->EncodeAudioBuffer(audioRecord);
    EXPECT_FALSE(boolRet);
    ret = coder->Stop();
    EXPECT_EQ(ret, 1);
}

/*
 * Feature: Framework
 * Function: Test AudioEncoder release normal branches.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test AudioEncoder release normal branches.
 */
HWTEST_F(AudioEncoderUnitTest, audio_encoder_unittest_004, TestSize.Level0)
{
    std::string codecMime = "OH_AVCODEC_MIMETYPE_AUDIO_AAC";
    std::shared_ptr<AudioEncoder> coder = std::make_shared<AudioEncoder>();
    int32_t ret = coder->Config();
    EXPECT_EQ(ret, 1);
    ret = coder->Start();
    EXPECT_EQ(ret, 1);
    ret = coder->Stop();
    EXPECT_EQ(ret, 1);
}
} // CameraStandard
} // OHOS
