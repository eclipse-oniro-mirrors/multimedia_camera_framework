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

#include "hcamera_movie_file_output_fuzzer.h"
#include "message_parcel.h"
#include "securec.h"
#include "camera_log.h"
#include "camera_manager.h"
#include "camera_device.h"
#include "capture_input.h"
#include "picture_proxy.h"
#include "hcamera_movie_file_output.h"
#include <fuzzer/FuzzedDataProvider.h>
#include "fuzz_util.h"
#include "test_token.h"

using namespace OHOS;
using namespace OHOS::CameraStandard;
HCameraMovieFileOutput& GetInstance()
{
    const int32_t FORMAT = CAMERA_FORMAT_RGBA_8888;
    const int32_t WIDTH = 1920;
    const int32_t HEIGHT = 1080;
    HCameraMovieFileOutput::MovieFileOutputFrameRateRange frameRange = { 30, 60 };
    static HCameraMovieFileOutput hCameraMovieFileOutput(FORMAT, WIDTH, HEIGHT, frameRange);
    return hCameraMovieFileOutput;
}
// static sptr<HCameraMovieFileOutput> g_hCameraMovieFileOutput;

void Start(FuzzedDataProvider& fdp)
{
    GetInstance().Start();
}

void Stop(FuzzedDataProvider& fdp)
{
    GetInstance().Stop();
}

void Pause(FuzzedDataProvider& fdp)
{
    GetInstance().Pause();
}

void Resume(FuzzedDataProvider& fdp)
{
    GetInstance().Resume();
}

void SetOutputSettings(FuzzedDataProvider& fdp)
{
    MovieSettings settings { PickEnumInRange(fdp, VideoCodecType::VIDEO_ENCODE_TYPE_HEVC),
        fdp.ConsumeIntegral<int32_t>(), fdp.ConsumeBool(),
        { fdp.ConsumeFloatingPoint<float>(), fdp.ConsumeFloatingPoint<float>(), fdp.ConsumeFloatingPoint<float>() },
        fdp.ConsumeBool(), fdp.ConsumeIntegral<int32_t>() };
    GetInstance().SetOutputSettings(settings);
}

void GetSupportedVideoFilters(FuzzedDataProvider& fdp)
{
    std::vector<std::string> filters;
    GetInstance().GetSupportedVideoFilters(filters);
}

void SetMovieFileOutputCallback(FuzzedDataProvider& fdp)
{
    auto cb = sptr<MockMovieFileOutputCallback>::MakeSptr();
    GetInstance().SetMovieFileOutputCallback(cb);
}

void UnsetMovieFileOutputCallback(FuzzedDataProvider& fdp)
{
    GetInstance().UnsetMovieFileOutputCallback();
}

void AddVideoFilter(FuzzedDataProvider& fdp)
{
    GetInstance().AddVideoFilter(fdp.ConsumeRandomLengthString(), fdp.ConsumeRandomLengthString());
}

void RemoveVideoFilter(FuzzedDataProvider& fdp)
{
    GetInstance().RemoveVideoFilter(fdp.ConsumeRandomLengthString());
}

void EnableMirror(FuzzedDataProvider& fdp)
{
    GetInstance().EnableMirror(fdp.ConsumeBool());
}

void IsMirrorEnabled(FuzzedDataProvider& fdp)
{
    bool isEnable;
    GetInstance().IsMirrorEnabled(isEnable);
}

void Release(FuzzedDataProvider& fdp)
{
    GetInstance().Release();
}

void GetSupportedVideoCapability(FuzzedDataProvider& fdp)
{
    std::shared_ptr<MediaCapabilityProxy> mediaCapability;
    GetInstance().GetSupportedVideoCapability(fdp.ConsumeIntegral<int32_t>(), mediaCapability);
}

void Init()
{
    CHECK_RETURN_ELOG(!TestToken().GetAllCameraPermission(), "Get permission fail");
}

void Test(FuzzedDataProvider& fdp)
{
    auto func = fdp.PickValueInArray({
    Start,
    Stop,
    Pause,
    Resume,
    SetOutputSettings,
    GetSupportedVideoFilters,
    SetMovieFileOutputCallback,
    UnsetMovieFileOutputCallback,
    AddVideoFilter,
    RemoveVideoFilter,
    EnableMirror,
    IsMirrorEnabled,
    Release,
    GetSupportedVideoCapability,
    });
    func(fdp);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    Test(fdp);
    return 0;
}

extern "C" int LLVMFuzzerInitialize(int* argc, char*** argv)
{
    if (SetSelfTokenID(718336240ull | (1ull << 32)) < 0) {
        return -1;
    }
    Init();
    return 0;
}