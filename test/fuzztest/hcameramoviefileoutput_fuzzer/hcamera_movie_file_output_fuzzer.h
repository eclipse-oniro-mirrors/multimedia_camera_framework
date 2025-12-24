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

#ifndef HCAMERA_MOVIE_FILE_OUTPUT_FUZZER_H
#define HCAMERA_MOVIE_FILE_OUTPUT_FUZZER_H

#include "system_ability_definition.h"
#include "camera_log.h"
#include <fuzzer/FuzzedDataProvider.h>
#include "movie_file_output_callback_stub.h"

namespace OHOS {
namespace CameraStandard {
class MockMovieFileOutputCallback : public MovieFileOutputCallbackStub {
public:
    ErrCode OnRecordingStart() override
    {
        return 0;
    }

    ErrCode OnRecordingPause() override
    {
        return 0;
    }

    ErrCode OnRecordingResume() override
    {
        return 0;
    }

    ErrCode OnRecordingStop() override
    {
        return 0;
    }

    ErrCode OnMovieInfoAvailable(int32_t captureId, const std::string& uri) override
    {
        return 0;
    }

    ErrCode OnError(int32_t errorCode) override
    {
        return 0;
    }
};
} // namespace CameraStandard
} // namespace OHOS
#endif // HCAMERA_MOVIE_FILE_OUTPUT_FUZZER_H