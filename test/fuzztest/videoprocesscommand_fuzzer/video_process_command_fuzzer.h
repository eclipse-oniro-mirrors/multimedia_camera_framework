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

#ifndef VIDEO_PROCESS_COMMAND_FUZZER_H
#define VIDEO_PROCESS_COMMAND_FUZZER_H

#include "video_process_command.h"
namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing{

class VideoProcessCommandFuzzer {
public:
static void VideoProcessCommandFuzzTest();

class VideoProcessCommandFuzz : public VideoProcessCommand{
public:
    VideoProcessCommandFuzz(const int32_t userId) : VideoProcessCommand(userId) {}
    int32_t Executing() override
    {
        return 0;
    }
    const char* GetCommandName() const override
    {
        return "0";
    }
};

class VideoProcessSuccessFuzz : public VideoProcessSuccessCommand{
public:
    VideoProcessSuccessFuzz(const int32_t userId,
        const std::string& videoId) : VideoProcessSuccessCommand(userId, videoId) {}
    int32_t Executing() override
    {
        return 0;
    }
    const char* GetCommandName() const override
    {
        return "0";
    }
};

class VideoProcessFailedFuzz : public VideoProcessFailedCommand{
public:
    VideoProcessFailedFuzz(const int32_t userId, const std::string& videoId,
        DpsError errorCode) : VideoProcessFailedCommand(userId, videoId, errorCode) {}
    int32_t Executing() override
    {
        return 0;
    }
    const char* GetCommandName() const override
    {
        return "0";
    }
};
};
}
}
}
#endif

