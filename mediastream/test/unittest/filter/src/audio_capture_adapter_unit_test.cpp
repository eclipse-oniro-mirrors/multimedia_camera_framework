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

#include "audio_capture_adapter_unit_test.h"

#include <token_setproc.h>
#include <accesstoken_kit.h>
#include "test_token.h"

using namespace OHOS;
using namespace OHOS::Media;
using namespace testing::ext;
using namespace Security::AccessToken;
namespace OHOS {
namespace CameraStandard {
namespace {
    const int32_t VALUE_THOUSAND = 1000;
}
void AudioCaptureAdapterUnitTest::SetUpTestCase(void)
{
    ASSERT_TRUE(TestToken().GetAllCameraPermission());
}

void AudioCaptureAdapterUnitTest::TearDownTestCase(void)
{
}

void AudioCaptureAdapterUnitTest::SetUp(void)
{
    appUid_ = static_cast<int32_t>(getuid());
    appTokenId_ = VALUE_THOUSAND;
    audioCaptureParameter_ = std::make_shared<Meta>();
    audioCaptureParameter_->Set<Tag::APP_TOKEN_ID>(appTokenId_);
    audioCaptureParameter_->Set<Tag::APP_UID>(appUid_);
    audioCaptureParameter_->Set<Tag::APP_PID>(appPid_);
    audioCaptureParameter_->Set<Tag::APP_FULL_TOKEN_ID>(appFullTokenId_);
    audioCaptureParameter_->Set<Tag::AUDIO_SAMPLE_FORMAT>(Plugins::AudioSampleFormat::SAMPLE_S16LE);
    audioCaptureParameter_->Set<Tag::AUDIO_SAMPLE_RATE>(sampleRate_);
    audioCaptureParameter_->Set<Tag::AUDIO_CHANNEL_COUNT>(channel_);
    audioCaptureParameter_->Set<Tag::MEDIA_BITRATE>(bitRate_);
    audioCaptureAdapter_ = std::make_shared<AudioCaptureAdapter>();
}

void AudioCaptureAdapterUnitTest::TearDown(void)
{
    audioCaptureParameter_.reset();
    audioCaptureAdapter_.reset();
}

class CapturerInfoChangeCallback : public AudioStandard::AudioCapturerInfoChangeCallback {
public:
    explicit CapturerInfoChangeCallback() { }
    void OnStateChange(const AudioStandard::AudioCapturerChangeInfo &info)
    {
        (void)info;
        std::cout << "AudioCapturerInfoChangeCallback" << std::endl;
    }
};

class AudioCaptureAdapterCallbackTest : public AudioCaptureAdapterCallback {
public:
    explicit AudioCaptureAdapterCallbackTest() { }
    void OnInterrupt(const std::string &interruptInfo) override
    {
        std::cout << "AudioCaptureAdapterCallback interrupt" << interruptInfo << std::endl;
    }
};

/**
 * @tc.name: AVSource_CreateSourceWithFD_1000
 * @tc.desc: create source with fd, mp4
 * @tc.type: FUNC
 */
HWTEST_F(AudioCaptureAdapterUnitTest, AudioCaptureInit_1000, TestSize.Level1)
{
    audioCaptureAdapter_->SetAudioSource(AudioStandard::SourceType::SOURCE_TYPE_MIC);
    std::shared_ptr<Meta> audioCaptureFormat = std::make_shared<Meta>();
    audioCaptureFormat->Set<Tag::APP_TOKEN_ID>(appTokenId_);
    audioCaptureFormat->Set<Tag::APP_UID>(appUid_);
    audioCaptureFormat->Set<Tag::APP_PID>(appPid_);
    audioCaptureFormat->Set<Tag::APP_FULL_TOKEN_ID>(appFullTokenId_);
    audioCaptureFormat->Set<Tag::AUDIO_SAMPLE_FORMAT>(Plugins::AudioSampleFormat::SAMPLE_S16LE);
    audioCaptureFormat->Set<Tag::AUDIO_SAMPLE_RATE>(sampleRate_);
    audioCaptureFormat->Set<Tag::AUDIO_CHANNEL_COUNT>(channel_);
    audioCaptureFormat->Set<Tag::MEDIA_BITRATE>(bitRate_);
    Status ret = audioCaptureAdapter_->SetParameter(audioCaptureFormat);
    ASSERT_TRUE(ret == Status::OK);
    ret = audioCaptureAdapter_->Init();
    ASSERT_TRUE(ret == Status::OK);
    ret = audioCaptureAdapter_->Deinit();
    ASSERT_TRUE(ret == Status::OK);
}

HWTEST_F(AudioCaptureAdapterUnitTest, AudioCaptureInit_1001, TestSize.Level1)
{
    audioCaptureAdapter_->SetAudioSource(AudioStandard::SourceType::SOURCE_TYPE_MIC);
    std::shared_ptr<Meta> audioCaptureFormat = std::make_shared<Meta>();
    Status ret = audioCaptureAdapter_->SetParameter(audioCaptureFormat);
    ASSERT_TRUE(ret == Status::OK);
}

HWTEST_F(AudioCaptureAdapterUnitTest, AudioCaptureInit_1002, TestSize.Level1)
{
    audioCaptureAdapter_->SetAudioSource(AudioStandard::SourceType::SOURCE_TYPE_MIC);
    std::shared_ptr<Meta> audioCaptureFormat = std::make_shared<Meta>();
    audioCaptureFormat->Set<Tag::AUDIO_SAMPLE_RATE>(sampleRate_);
    Status ret = audioCaptureAdapter_->SetParameter(audioCaptureFormat);
    ASSERT_TRUE(ret == Status::OK);
}

HWTEST_F(AudioCaptureAdapterUnitTest, AudioCaptureInit_1003, TestSize.Level1)
{
    audioCaptureAdapter_->SetAudioSource(AudioStandard::SourceType::SOURCE_TYPE_MIC);
    std::shared_ptr<Meta> audioCaptureFormat = std::make_shared<Meta>();
    audioCaptureFormat->Set<Tag::AUDIO_SAMPLE_RATE>(sampleRate_);
    audioCaptureFormat->Set<Tag::AUDIO_CHANNEL_COUNT>(channel_);
    Status ret = audioCaptureAdapter_->SetParameter(audioCaptureFormat);
    ASSERT_TRUE(ret == Status::OK);
}

HWTEST_F(AudioCaptureAdapterUnitTest, AudioCapturePrepare_1000, TestSize.Level1)
{
    audioCaptureAdapter_->SetAudioSource(AudioStandard::SourceType::SOURCE_TYPE_MIC);
    std::shared_ptr<Meta> audioCaptureFormat = std::make_shared<Meta>();
    audioCaptureFormat->Set<Tag::APP_TOKEN_ID>(appTokenId_);
    audioCaptureFormat->Set<Tag::APP_UID>(appUid_);
    audioCaptureFormat->Set<Tag::APP_PID>(appPid_);
    audioCaptureFormat->Set<Tag::APP_FULL_TOKEN_ID>(appFullTokenId_);
    audioCaptureFormat->Set<Tag::AUDIO_SAMPLE_FORMAT>(Plugins::AudioSampleFormat::SAMPLE_S16LE);
    audioCaptureFormat->Set<Tag::AUDIO_SAMPLE_RATE>(sampleRate_);
    audioCaptureFormat->Set<Tag::AUDIO_CHANNEL_COUNT>(channel_);
    audioCaptureFormat->Set<Tag::MEDIA_BITRATE>(bitRate_);
    Status ret = audioCaptureAdapter_->SetParameter(audioCaptureFormat);
    ASSERT_TRUE(ret == Status::OK);
    ret = audioCaptureAdapter_->Init();
    ASSERT_TRUE(ret == Status::OK);
    ret = audioCaptureAdapter_->Prepare();
    ASSERT_TRUE(ret == Status::OK);
    ret = audioCaptureAdapter_->Deinit();
    ASSERT_TRUE(ret == Status::OK);
}

HWTEST_F(AudioCaptureAdapterUnitTest, AudioCaptureStart_1000, TestSize.Level1)
{
    audioCaptureAdapter_->SetAudioSource(AudioStandard::SourceType::SOURCE_TYPE_MIC);
    std::shared_ptr<Meta> audioCaptureFormat = std::make_shared<Meta>();
    audioCaptureFormat->Set<Tag::APP_TOKEN_ID>(appTokenId_);
    audioCaptureFormat->Set<Tag::APP_UID>(appUid_);
    audioCaptureFormat->Set<Tag::APP_PID>(appPid_);
    audioCaptureFormat->Set<Tag::APP_FULL_TOKEN_ID>(appFullTokenId_);
    audioCaptureFormat->Set<Tag::AUDIO_SAMPLE_FORMAT>(Plugins::AudioSampleFormat::SAMPLE_S16LE);
    audioCaptureFormat->Set<Tag::AUDIO_SAMPLE_RATE>(sampleRate_);
    audioCaptureFormat->Set<Tag::AUDIO_CHANNEL_COUNT>(channel_);
    audioCaptureFormat->Set<Tag::MEDIA_BITRATE>(bitRate_);
    Status ret = audioCaptureAdapter_->SetParameter(audioCaptureFormat);
    ASSERT_TRUE(ret == Status::OK);
    ret = audioCaptureAdapter_->Init();
    ASSERT_TRUE(ret == Status::OK);
    ret = audioCaptureAdapter_->Prepare();
    ASSERT_TRUE(ret == Status::OK);
    ret = audioCaptureAdapter_->Start();
    ASSERT_TRUE(ret == Status::OK);
    ret = audioCaptureAdapter_->Stop();
    ASSERT_TRUE(ret == Status::OK);
    ret = audioCaptureAdapter_->Deinit();
    ASSERT_TRUE(ret == Status::OK);
}

HWTEST_F(AudioCaptureAdapterUnitTest, AudioCaptureRead_0100, TestSize.Level1)
{
    audioCaptureAdapter_->SetAudioSource(AudioStandard::SourceType::SOURCE_TYPE_MIC);
    std::shared_ptr<Meta> audioCaptureFormat = std::make_shared<Meta>();
    audioCaptureFormat->Set<Tag::APP_TOKEN_ID>(appTokenId_);
    audioCaptureFormat->Set<Tag::APP_UID>(appUid_);
    audioCaptureFormat->Set<Tag::APP_PID>(appPid_);
    audioCaptureFormat->Set<Tag::APP_FULL_TOKEN_ID>(appFullTokenId_);
    audioCaptureFormat->Set<Tag::AUDIO_SAMPLE_FORMAT>(Plugins::AudioSampleFormat::SAMPLE_S16LE);
    audioCaptureFormat->Set<Tag::AUDIO_SAMPLE_RATE>(sampleRate_);
    audioCaptureFormat->Set<Tag::AUDIO_CHANNEL_COUNT>(channel_);
    audioCaptureFormat->Set<Tag::MEDIA_BITRATE>(bitRate_);
    Status ret = audioCaptureAdapter_->SetParameter(audioCaptureFormat);
    ASSERT_TRUE(ret == Status::OK);
    ret = audioCaptureAdapter_->Init();
    ASSERT_TRUE(ret == Status::OK);
    ret = audioCaptureAdapter_->Prepare();
    ASSERT_TRUE(ret == Status::OK);
    ret = audioCaptureAdapter_->Start();
    ASSERT_TRUE(ret == Status::OK);
    uint64_t bufferSize = 0;
    ret = audioCaptureAdapter_->GetSize(bufferSize);
    ASSERT_TRUE(ret == Status::OK);
    std::shared_ptr<AVAllocator> avAllocator =
        AVAllocatorFactory::CreateSharedAllocator(MemoryFlag::MEMORY_READ_WRITE);
    int32_t capacity = 1024;
    std::shared_ptr<AVBuffer> buffer = AVBuffer::CreateAVBuffer(avAllocator, capacity);
    ret = audioCaptureAdapter_->Read(buffer, bufferSize);
    ASSERT_TRUE(ret == Status::OK);
    ret = audioCaptureAdapter_->Stop();
    ASSERT_TRUE(ret == Status::OK);
    ret = audioCaptureAdapter_->Deinit();
    ASSERT_TRUE(ret == Status::OK);
}

HWTEST_F(AudioCaptureAdapterUnitTest, AudioCaptureRead_0200, TestSize.Level1)
{
    std::shared_ptr<AVAllocator> avAllocator =
        AVAllocatorFactory::CreateSharedAllocator(MemoryFlag::MEMORY_READ_WRITE);
    std::shared_ptr<AVBuffer> buffer = AVBuffer::CreateAVBuffer(avAllocator);
    size_t bufferSize = 1024;
    Status ret = audioCaptureAdapter_->Read(buffer, bufferSize);
    EXPECT_NE(ret, Status::OK);
}

HWTEST_F(AudioCaptureAdapterUnitTest, AudioCaptureRead_0300, TestSize.Level1)
{
    std::shared_ptr<AVAllocator> avAllocator =
        AVAllocatorFactory::CreateSharedAllocator(MemoryFlag::MEMORY_READ_WRITE);
    std::shared_ptr<AVBuffer> buffer = AVBuffer::CreateAVBuffer(avAllocator);
    buffer->meta_ = nullptr;
    size_t bufferSize = 1024;
    Status ret = audioCaptureAdapter_->Read(buffer, bufferSize);
    EXPECT_NE(ret, Status::OK);
}

HWTEST_F(AudioCaptureAdapterUnitTest, AudioCaptureRead_0400, TestSize.Level1)
{
    audioCaptureAdapter_->SetAudioSource(AudioStandard::SourceType::SOURCE_TYPE_MIC);
    Status ret = audioCaptureAdapter_->SetParameter(audioCaptureParameter_);
    ASSERT_TRUE(ret == Status::OK);
    ret = audioCaptureAdapter_->Init();
    ASSERT_TRUE(ret == Status::OK);
    ret = audioCaptureAdapter_->Prepare();
    ASSERT_TRUE(ret == Status::OK);
    uint64_t bufferSize = 0;
    ret = audioCaptureAdapter_->GetSize(bufferSize);
    ASSERT_TRUE(ret == Status::OK);
    std::shared_ptr<AVAllocator> avAllocator =
    AVAllocatorFactory::CreateSharedAllocator(MemoryFlag::MEMORY_READ_WRITE);
    int32_t capacity = 1024;
    std::shared_ptr<AVBuffer> buffer = AVBuffer::CreateAVBuffer(avAllocator, capacity);
    EXPECT_NE(Status::OK, audioCaptureAdapter_->Read(buffer, bufferSize));
    ret = audioCaptureAdapter_->Deinit();
    ASSERT_TRUE(ret == Status::OK);
}

/**
 * @tc.name: AudioCaptureGetCurrentChangeInfo_0100
 * @tc.desc: test GetCurrentChangeInfo
 * @tc.type: FUNC
 */
HWTEST_F(AudioCaptureAdapterUnitTest, AudioCaptureGetCurrentChangeInfo_0100, TestSize.Level1)
{
    audioCaptureAdapter_->SetAudioSource(AudioStandard::SourceType::SOURCE_TYPE_MIC);
    Status ret = audioCaptureAdapter_->SetParameter(audioCaptureParameter_);
    ASSERT_TRUE(ret == Status::OK);
    ret = audioCaptureAdapter_->Init();
    ASSERT_TRUE(ret == Status::OK);
    ret = audioCaptureAdapter_->Prepare();
    ASSERT_TRUE(ret == Status::OK);
    AudioStandard::AudioCapturerChangeInfo changeInfo;
    audioCaptureAdapter_->GetCurrentCapturerChangeInfo(changeInfo);
    ret = audioCaptureAdapter_->Deinit();
    ASSERT_TRUE(ret == Status::OK);
}

/**
 * @tc.name: AudioCaptureGetCurrentChangeInfo_0200
 * @tc.desc: test GetCurrentChangeInfo
 * @tc.type: FUNC
 */
HWTEST_F(AudioCaptureAdapterUnitTest, AudioCaptureGetCurrentChangeInfo_0200, TestSize.Level1)
{
    AudioStandard::AudioCapturerChangeInfo changeInfo;
    audioCaptureAdapter_->GetCurrentCapturerChangeInfo(changeInfo);
    Status ret = audioCaptureAdapter_->Deinit();
    ASSERT_TRUE(ret == Status::OK);
}

/**
 * @tc.name: AudioCaptureSetCallingInfo_0100
 * @tc.desc: test SetCallingInfo
 * @tc.type: FUNC
 */
HWTEST_F(AudioCaptureAdapterUnitTest, AudioCaptureSetCallingInfo_0100, TestSize.Level1)
{
    audioCaptureAdapter_->SetCallingInfo(appUid_, appPid_, bundleName_, instanceId_);
    Status ret = audioCaptureAdapter_->Deinit();
    ASSERT_TRUE(ret == Status::OK);
}

/**
 * @tc.name: AudioCaptureGetMaxAmplitude_0100
 * @tc.desc: test GetMaxAmplitude
 * @tc.type: FUNC
 */
HWTEST_F(AudioCaptureAdapterUnitTest, AudioCaptureGetMaxAmplitude_0100, TestSize.Level1)
{
    audioCaptureAdapter_->SetAudioSource(AudioStandard::SourceType::SOURCE_TYPE_MIC);
    Status ret = audioCaptureAdapter_->SetParameter(audioCaptureParameter_);
    ASSERT_TRUE(ret == Status::OK);
    ret = audioCaptureAdapter_->Init();
    ASSERT_TRUE(ret == Status::OK);
    ret = audioCaptureAdapter_->Prepare();
    ASSERT_TRUE(ret == Status::OK);
    ret = audioCaptureAdapter_->Start();
    ASSERT_TRUE(ret == Status::OK);
    uint64_t bufferSize = 0;
    ret = audioCaptureAdapter_->GetSize(bufferSize);
    ASSERT_TRUE(ret == Status::OK);
    audioCaptureAdapter_->isTrackMaxAmplitude = false;
    audioCaptureAdapter_->GetMaxAmplitude();
    audioCaptureAdapter_->isTrackMaxAmplitude = true;
    EXPECT_EQ(audioCaptureAdapter_->maxAmplitude_, audioCaptureAdapter_->GetMaxAmplitude());
    std::shared_ptr<AVAllocator> avAllocator =
        AVAllocatorFactory::CreateSharedAllocator(MemoryFlag::MEMORY_READ_WRITE);
    int32_t capacity = 1024;
    std::shared_ptr<AVBuffer> buffer = AVBuffer::CreateAVBuffer(avAllocator, capacity);
    ret = audioCaptureAdapter_->Read(buffer, bufferSize);
    ASSERT_TRUE(ret == Status::OK);
    ret = audioCaptureAdapter_->Stop();
    ASSERT_TRUE(ret == Status::OK);
    ret = audioCaptureAdapter_->Deinit();
    ASSERT_TRUE(ret == Status::OK);
}

/**
 * @tc.name: AudioSetAudioCapturerInfoChangeCallback_0100
 * @tc.desc: test SetAudioCapturerInfoChangeCallback
 * @tc.type: FUNC
 */
HWTEST_F(AudioCaptureAdapterUnitTest, AudioSetAudioCapturerInfoChangeCallback_0100, TestSize.Level1)
{
    EXPECT_NE(Status::OK, audioCaptureAdapter_->SetAudioCapturerInfoChangeCallback(nullptr));
    audioCaptureAdapter_->SetAudioSource(AudioStandard::SourceType::SOURCE_TYPE_MIC);
    Status ret = audioCaptureAdapter_->SetParameter(audioCaptureParameter_);
    ASSERT_TRUE(ret == Status::OK);
    ret = audioCaptureAdapter_->Init();
    ASSERT_TRUE(ret == Status::OK);
    EXPECT_NE(Status::OK, audioCaptureAdapter_->SetAudioCapturerInfoChangeCallback(nullptr));
    std::shared_ptr<AudioStandard::AudioCapturerInfoChangeCallback> callback =
        std::make_shared<CapturerInfoChangeCallback>();
    EXPECT_NE(Status::OK, audioCaptureAdapter_->SetAudioCapturerInfoChangeCallback(nullptr));
    ret = audioCaptureAdapter_->Deinit();
    ASSERT_TRUE(ret == Status::OK);
}

/**
 * @tc.name: AudioSetAudioInterruptListener_0100
 * @tc.desc: test SetAudioInterruptListener
 * @tc.type: FUNC
 */
HWTEST_F(AudioCaptureAdapterUnitTest, AudioSetAudioInterruptListener_0100, TestSize.Level1)
{
    EXPECT_NE(Status::OK, audioCaptureAdapter_->SetAudioInterruptListener(nullptr));
    std::shared_ptr<AudioCaptureAdapterCallback> callback =
        std::make_shared<AudioCaptureAdapterCallbackTest>();
    EXPECT_EQ(Status::OK, audioCaptureAdapter_->SetAudioInterruptListener(callback));
    Status ret = audioCaptureAdapter_->Deinit();
    ASSERT_TRUE(ret == Status::OK);
}

/**
 * @tc.name: AudioGetSize_0100
 * @tc.desc: test GetSize
 * @tc.type: FUNC
 */
HWTEST_F(AudioCaptureAdapterUnitTest, AudioGetSize_0100, TestSize.Level1)
{
    uint64_t size = 0;
    EXPECT_NE(Status::OK, audioCaptureAdapter_->GetSize(size));
    Status ret = audioCaptureAdapter_->Deinit();
    ASSERT_TRUE(ret == Status::OK);
}

/**
 * @tc.name: AudioGetSize_0200
 * @tc.desc: test GetSize
 * @tc.type: FUNC
 */
HWTEST_F(AudioCaptureAdapterUnitTest, AudioGetSize_0200, TestSize.Level1)
{
    uint64_t size = 0;
    EXPECT_NE(Status::OK, audioCaptureAdapter_->GetSize(size));
    Status ret = audioCaptureAdapter_->Deinit();
    ASSERT_TRUE(ret == Status::OK);
}

/**
 * @tc.name: AudioGetSize_0300
 * @tc.desc: test GetSize
 * @tc.type: FUNC
 */
HWTEST_F(AudioCaptureAdapterUnitTest, AudioGetSize_0300, TestSize.Level1)
{
    uint64_t size = 0;
    EXPECT_NE(Status::OK, audioCaptureAdapter_->GetSize(size));
    Status ret = audioCaptureAdapter_->Deinit();
    ASSERT_TRUE(ret == Status::OK);
}

/**
 * @tc.name: AudioSetParameter_0100
 * @tc.desc: test SetParameter
 * @tc.type: FUNC
 */
HWTEST_F(AudioCaptureAdapterUnitTest, AudioSetParameter_0100, TestSize.Level1)
{
    std::shared_ptr<Meta> audioCaptureFormat = std::make_shared<Meta>();
    audioCaptureAdapter_->SetParameter(audioCaptureFormat);
    audioCaptureFormat->Set<Tag::AUDIO_SAMPLE_RATE>(sampleRate_);
    audioCaptureAdapter_->SetParameter(audioCaptureFormat);
    audioCaptureFormat->Set<Tag::AUDIO_CHANNEL_COUNT>(channel_);
    audioCaptureAdapter_->SetParameter(audioCaptureFormat);
    audioCaptureFormat->Set<Tag::AUDIO_SAMPLE_FORMAT>(Plugins::AudioSampleFormat::SAMPLE_S16LE);
    Status ret = audioCaptureAdapter_->SetParameter(audioCaptureFormat);
    EXPECT_EQ(ret, Status::OK);
}

/**
 * @tc.name: AudioSetParameter_0200
 * @tc.desc: test SetParameter
 * @tc.type: FUNC
 */
HWTEST_F(AudioCaptureAdapterUnitTest, AudioSetParameter_0200, TestSize.Level1)
{
    std::shared_ptr<Meta> audioCaptureFormat = std::make_shared<Meta>();
    audioCaptureFormat->Set<Tag::AUDIO_SAMPLE_FORMAT>(Plugins::AudioSampleFormat::SAMPLE_F32P);
    Status ret = audioCaptureAdapter_->SetParameter(audioCaptureFormat);
    EXPECT_NE(ret, Status::OK);
}

/**
 * @tc.name: AudioSetParameter_0300
 * @tc.desc: test SetParameter
 * @tc.type: FUNC
 */
HWTEST_F(AudioCaptureAdapterUnitTest, AudioSetParameter_0300, TestSize.Level1)
{
    int32_t channel = 100;
    audioCaptureParameter_->Set<Tag::AUDIO_CHANNEL_COUNT>(channel);
    Status ret = audioCaptureAdapter_->SetParameter(audioCaptureParameter_);
    EXPECT_EQ(ret, Status::ERROR_INVALID_PARAMETER);
}

/**
 * @tc.name: AudioGetParameter_0100
 * @tc.desc: test GetParameter
 * @tc.type: FUNC
 */
HWTEST_F(AudioCaptureAdapterUnitTest, AudioGetParameter_0100, TestSize.Level1)
{
    audioCaptureAdapter_->SetAudioSource(AudioStandard::SourceType::SOURCE_TYPE_MIC);
    std::shared_ptr<Meta> audioCaptureParameterTest_ = std::make_shared<Meta>();
    Status ret = audioCaptureAdapter_->SetParameter(audioCaptureParameter_);
    EXPECT_NE(Status::OK, audioCaptureAdapter_->GetParameter(audioCaptureParameterTest_));
    ASSERT_TRUE(ret == Status::OK);
    ret = audioCaptureAdapter_->Init();
    ASSERT_TRUE(ret == Status::OK);
    ret = audioCaptureAdapter_->Prepare();
    ASSERT_TRUE(ret == Status::OK);
    audioCaptureAdapter_->GetParameter(audioCaptureParameterTest_);

    audioCaptureParameter_->Set<Tag::AUDIO_SAMPLE_FORMAT>(Plugins::AudioSampleFormat::SAMPLE_U8);
    audioCaptureAdapter_->SetParameter(audioCaptureParameter_);
    audioCaptureAdapter_->GetParameter(audioCaptureParameterTest_);
    int32_t channel = 2;
    audioCaptureParameter_->Set<Tag::AUDIO_CHANNEL_COUNT>(channel);
    audioCaptureAdapter_->SetParameter(audioCaptureParameter_);
    audioCaptureAdapter_->GetParameter(audioCaptureParameterTest_);
    int32_t sampleRate = 64000;
    audioCaptureParameter_->Set<Tag::AUDIO_SAMPLE_RATE>(sampleRate);
    audioCaptureAdapter_->SetParameter(audioCaptureParameter_);
    audioCaptureAdapter_->GetParameter(audioCaptureParameterTest_);
    ret = audioCaptureAdapter_->Deinit();
    ASSERT_TRUE(ret == Status::OK);
}

/**
 * @tc.name: AudioReset_0100
 * @tc.desc: test Reset
 * @tc.type: FUNC
 */
HWTEST_F(AudioCaptureAdapterUnitTest, AudioReset_0100, TestSize.Level1)
{
    audioCaptureAdapter_->SetAudioSource(AudioStandard::SourceType::SOURCE_TYPE_MIC);
    Status ret = audioCaptureAdapter_->SetParameter(audioCaptureParameter_);
    ASSERT_TRUE(ret == Status::OK);
    ret = audioCaptureAdapter_->Init();
    ASSERT_TRUE(ret == Status::OK);
    ret = audioCaptureAdapter_->Prepare();
    ASSERT_TRUE(ret == Status::OK);
    ret = audioCaptureAdapter_->Start();
    ASSERT_TRUE(ret == Status::OK);
    uint64_t bufferSize = 0;
    ret = audioCaptureAdapter_->GetSize(bufferSize);
    ASSERT_TRUE(ret == Status::OK);
    std::shared_ptr<AVAllocator> avAllocator =
        AVAllocatorFactory::CreateSharedAllocator(MemoryFlag::MEMORY_READ_WRITE);
    int32_t capacity = 1024;
    std::shared_ptr<AVBuffer> buffer = AVBuffer::CreateAVBuffer(avAllocator, capacity);
    ret = audioCaptureAdapter_->Read(buffer, bufferSize);
    ASSERT_TRUE(ret == Status::OK);
    ret = audioCaptureAdapter_->Stop();
    ASSERT_TRUE(ret == Status::OK);
    ret = audioCaptureAdapter_->Reset();
    ASSERT_TRUE(ret == Status::OK);
    ret = audioCaptureAdapter_->Deinit();
    ASSERT_TRUE(ret == Status::OK);
}

/**
 * @tc.name: AudioReset_0200
 * @tc.desc: test Reset
 * @tc.type: FUNC
 */
HWTEST_F(AudioCaptureAdapterUnitTest, AudioReset_0200, TestSize.Level1)
{
    audioCaptureAdapter_->SetAudioSource(AudioStandard::SourceType::SOURCE_TYPE_MIC);
    Status ret = audioCaptureAdapter_->SetParameter(audioCaptureParameter_);
    ASSERT_TRUE(ret == Status::OK);
    ret = audioCaptureAdapter_->Init();
    ASSERT_TRUE(ret == Status::OK);
    ret = audioCaptureAdapter_->Prepare();
    ASSERT_TRUE(ret == Status::OK);
    ret = audioCaptureAdapter_->Reset();
    ASSERT_TRUE(ret == Status::OK);
    ret = audioCaptureAdapter_->Deinit();
    ASSERT_TRUE(ret == Status::OK);
}

/**
 * @tc.name: Audioinit_0100
 * @tc.desc: test init
 * @tc.type: FUNC
 */
HWTEST_F(AudioCaptureAdapterUnitTest, Audioinit_0100, TestSize.Level1)
{
    audioCaptureAdapter_->SetAudioSource(AudioStandard::SourceType::SOURCE_TYPE_MIC);
    Status ret = audioCaptureAdapter_->SetParameter(audioCaptureParameter_);
    ASSERT_TRUE(ret == Status::OK);
    ret = audioCaptureAdapter_->Init();
    ASSERT_TRUE(ret == Status::OK);
    ret = audioCaptureAdapter_->Init();
    ASSERT_TRUE(ret == Status::OK);
    ret = audioCaptureAdapter_->Deinit();
    ASSERT_TRUE(ret == Status::OK);
}

/**
 * @tc.name: Audioinit_0200
 * @tc.desc: test init
 * @tc.type: FUNC
 */
HWTEST_F(AudioCaptureAdapterUnitTest, Audioinit_0200, TestSize.Level1)
{
    audioCaptureAdapter_->SetAudioSource(AudioStandard::SourceType::SOURCE_TYPE_MIC);
    EXPECT_NE(Status::OK, audioCaptureAdapter_->Init());
    Status ret = audioCaptureAdapter_->Deinit();
    ASSERT_TRUE(ret == Status::OK);
}

/**
 * @tc.name: AudioTrackMaxAmplitude_0200
 * @tc.desc: test TrackMaxAmplitude
 * @tc.type: FUNC
 */
HWTEST_F(AudioCaptureAdapterUnitTest, AudioTrackMaxAmplitude_0200, TestSize.Level1)
{
    int16_t data[5] = {1, 2, 3, 4, 5};
    audioCaptureAdapter_->TrackMaxAmplitude(data, 5);
    EXPECT_EQ(audioCaptureAdapter_->maxAmplitude_, 5);
    int16_t number[5] = {1, -2, 3, -4, 5};
    audioCaptureAdapter_->TrackMaxAmplitude(number, 5);
    EXPECT_EQ(audioCaptureAdapter_->maxAmplitude_, 5);
}

/**
 * @tc.name: AudioGetMaxAmplitude_0200
 * @tc.desc: test GetMaxAmplitude
 * @tc.type: FUNC
 */
HWTEST_F(AudioCaptureAdapterUnitTest, AudioGetMaxAmplitude_0200, TestSize.Level1)
{
    audioCaptureAdapter_->isTrackMaxAmplitude = true;
    EXPECT_EQ(audioCaptureAdapter_->GetMaxAmplitude(), 0);
}
} // CameraStandard
} // namespace OHOS