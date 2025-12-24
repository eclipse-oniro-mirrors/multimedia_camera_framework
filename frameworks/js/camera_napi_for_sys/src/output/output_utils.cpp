/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "output/depth_data_output_napi.h"
#include "output/movie_file_output_napi.h"

namespace OHOS {
namespace CameraStandard {
extern "C" bool checkAndGetOutput(napi_env env, napi_value obj, sptr<CaptureOutput> &output)
{
    if (DepthDataOutputNapi::IsDepthDataOutput(env, obj)) {
        MEDIA_DEBUG_LOG("depth data output adding..");
        DepthDataOutputNapi* depthDataOutputNapiObj = nullptr;
        napi_unwrap(env, obj, reinterpret_cast<void**>(&depthDataOutputNapiObj));
        CHECK_RETURN_RET_ELOG(depthDataOutputNapiObj == nullptr, false, "depthDataOutputNapiObj unwrap fail");
        output = depthDataOutputNapiObj->GetDepthDataOutput();
    } else if (MovieFileOutputNapi::IsMovieFileOutput(env, obj)) {
        MEDIA_DEBUG_LOG("movie file output adding..");
        MovieFileOutputNapi* movieFileOutputNapiObj = nullptr;
        napi_unwrap(env, obj, reinterpret_cast<void**>(&movieFileOutputNapiObj));
        CHECK_RETURN_RET_ELOG(movieFileOutputNapiObj == nullptr, false, "movieFileOutputNapiObj unwrap fail");
        output = movieFileOutputNapiObj->GetMovieFileOutput();
    } else {
        return false;
    }
    return true;
}
} // namespace CameraStandard
} // namespace OHOS
