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

#ifndef OHOS_CAMERA_MOVIE_FILE_COMMON_CONST_H
#define OHOS_CAMERA_MOVIE_FILE_COMMON_CONST_H

#include <cstdint>
#include "camera_util.h"

namespace OHOS {
namespace CameraStandard {
constexpr int32_t MOVIE_FILE_VIDEO_DEFAULT_SIZE = 1920 * 1440;
constexpr float MOVIE_FILE_VIDEO_BITRATE_CONSTANT = 0.7;
constexpr int32_t MOVIE_FILE_VIDEO_BITRATE_22M = 22 * 1000 * 1000; // 22Mbps
constexpr double MOVIE_FILE_VIDEO_FRAME_RATE = 30.0;
constexpr int32_t MOVIE_FILE_BUFFER_ENCODE_WAIT_IFRAME_TIME = 100;

constexpr uint32_t MOVIE_FILE_AUDIO_SAMPLE_RATE_32000 = 32000;
constexpr uint32_t MOVIE_FILE_AUDIO_DEFAULT_CHANNEL_COUNT = 1;
constexpr uint32_t MOVIE_FILE_AUDIO_DEFAULT_PROFILE = 0;
constexpr uint64_t MOVIE_FILE_AUDIO_DEFAULT_BITRATE = 192000;
constexpr uint64_t MOVIE_FILE_AUDIO_HIGH_BITRATE = 384000;
constexpr uint32_t MOVIE_FILE_AUDIO_DEFAULT_MAX_INPUT_SIZE =
    1024 * MOVIE_FILE_AUDIO_DEFAULT_CHANNEL_COUNT * sizeof(short);

constexpr int32_t MOVIE_FILE_AUDIO_ONE_THOUSAND = 1000;
constexpr int32_t MOVIE_FILE_AUDIO_DURATION_EACH_AUDIO_FRAME = 32;
constexpr int32_t MOVIE_FILE_AUDIO_PROCESS_BATCH_SIZE = 5;
constexpr int32_t MOVIE_FILE_AUDIO_MAX_UNPROCESSED_SIZE = 12288;
constexpr int32_t MOVIE_FILE_AUDIO_MAX_PROCESSED_SIZE = 2048;
constexpr int32_t MOVIE_FILE_AUDIO_READ_WAIT_TIME = 5;
constexpr int32_t MOVIE_FILE_AUDIO_ENCODE_EXPIRATION_TIME = 10;
constexpr int32_t MOVIE_FILE_AUDIO_INPUT_RETRY_TIMES = 6;
constexpr int32_t MOVIE_FILE_AUDIO_OUTPUT_RETRY_TIMES = 3;

constexpr int32_t MILLISEC_TO_MICROSEC = 1000;
} // namespace CameraStandard
} // namespace OHOS

#endif