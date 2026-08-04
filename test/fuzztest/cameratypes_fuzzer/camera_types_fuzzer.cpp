/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "camera_types_fuzzer.h"
#include "camera_log.h"
#include <cstddef>
#include <cstdint>
#include <memory>
#include "ipc_skeleton.h"

namespace OHOS {
namespace CameraStandard {
static constexpr int32_t MAX_BUFFER_SIZE = 16;
static constexpr int32_t NUM_10 = 10;

void CameraTypesFuzz::CameraTypesFuzzTest(FuzzedDataProvider& fdp)
{
    int testType = fdp.ConsumeIntegralInRange<int>(0, 2);

    if (testType == 0) {
        TestBasicTypes(fdp);
    } else if (testType == 1) {
        TestComplexTypes(fdp);
    } else {
        TestErrorCases(fdp);
    }
}

void CameraTypesFuzz::TestBasicTypes(FuzzedDataProvider& fdp)
{
    EffectParam effectParam;
    effectParam.skinSmoothLevel = fdp.ConsumeIntegral<int32_t>();
    effectParam.faceSlender = fdp.ConsumeIntegral<int32_t>();
    effectParam.skinTone = fdp.ConsumeIntegral<int32_t>();
    effectParam.skinToneBright = fdp.ConsumeIntegral<int32_t>();
    effectParam.eyeBigEyes = fdp.ConsumeIntegral<int32_t>();
    effectParam.hairHairline = fdp.ConsumeIntegral<int32_t>();
    effectParam.faceMakeUp = fdp.ConsumeIntegral<int32_t>();
    effectParam.headShrink = fdp.ConsumeIntegral<int32_t>();
    effectParam.noseSlender = fdp.ConsumeIntegral<int32_t>();
    {
        MessageParcel data;
        EffectParamBlockMarshalling(data, effectParam);
        EffectParamBlockUnmarshalling(data, effectParam);
    }

    SketchStatusData sketchStatusData;
    sketchStatusData.status = static_cast<SketchStatus>(fdp.ConsumeIntegral<int32_t>());
    sketchStatusData.sketchRatio = fdp.ConsumeFloatingPoint<float>();
    sketchStatusData.offsetx = fdp.ConsumeFloatingPoint<float>();
    sketchStatusData.offsety = fdp.ConsumeFloatingPoint<float>();
    {
        MessageParcel data;
        SketchStatusDataBlockMarshalling(data, sketchStatusData);
        SketchStatusDataBlockUnmarshalling(data, sketchStatusData);
    }

    CaptureEndedInfoExt captureEndedInfoExt;
    captureEndedInfoExt.streamId = fdp.ConsumeIntegral<int32_t>();
    captureEndedInfoExt.frameCount = fdp.ConsumeIntegral<int32_t>();
    captureEndedInfoExt.isDeferredVideoEnhancementAvailable = fdp.ConsumeBool();
    captureEndedInfoExt.videoId = fdp.ConsumeRandomLengthString(NUM_10);
    captureEndedInfoExt.deferredVideoEnhanceFlag = fdp.ConsumeIntegral<uint32_t>();
    captureEndedInfoExt.eisStartInfo = fdp.ConsumeRandomLengthString(NUM_10);
    captureEndedInfoExt.cinemaKeyPts = fdp.ConsumeRandomLengthString(NUM_10);
    {
        MessageParcel data;
        CaptureEndedInfoExtBlockMarshalling(data, captureEndedInfoExt);
        CaptureEndedInfoExtBlockUnmarshalling(data, captureEndedInfoExt);
    }

    ControlCenterStatusInfo controlCenterStatusInfo;
    controlCenterStatusInfo.effectType = static_cast<ControlCenterEffectType>(fdp.ConsumeIntegral<int32_t>());
    controlCenterStatusInfo.isActive = fdp.ConsumeBool();
    {
        MessageParcel data;
        ControlCenterStatusInfoBlockMarshalling(data, controlCenterStatusInfo);
        ControlCenterStatusInfoBlockUnmarshalling(data, controlCenterStatusInfo);
    }

    IpcVideoProfile ipcVideoProfile;
    ipcVideoProfile.format = fdp.ConsumeIntegral<int32_t>();
    ipcVideoProfile.width = fdp.ConsumeIntegral<int32_t>();
    ipcVideoProfile.height = fdp.ConsumeIntegral<int32_t>();
    ipcVideoProfile.minFrameRate = fdp.ConsumeIntegral<int32_t>();
    ipcVideoProfile.maxFrameRate = fdp.ConsumeIntegral<int32_t>();
    {
        MessageParcel data;
        IpcVideoProfileBlockMarshalling(data, ipcVideoProfile);
        IpcVideoProfileBlockUnmarshalling(data, ipcVideoProfile);
    }

    Location location;
    location.latitude = fdp.ConsumeFloatingPoint<double>();
    location.longitude = fdp.ConsumeFloatingPoint<double>();
    location.altitude = fdp.ConsumeFloatingPoint<double>();
    {
        MessageParcel data;
        LocationBlockMarshalling(data, location);
        LocationBlockUnmarshalling(data, location);
    }

    MovieSettings movieSettings;
    movieSettings.videoCodecType = static_cast<VideoCodecType>(fdp.ConsumeIntegral<int32_t>());
    movieSettings.rotation = fdp.ConsumeIntegral<int32_t>();
    movieSettings.isHasLocation = fdp.ConsumeBool();
    movieSettings.location.latitude = fdp.ConsumeFloatingPoint<double>();
    movieSettings.location.longitude = fdp.ConsumeFloatingPoint<double>();
    movieSettings.location.altitude = fdp.ConsumeFloatingPoint<double>();
    movieSettings.isBFrameEnabled = fdp.ConsumeBool();
    movieSettings.videoBitrate = fdp.ConsumeIntegral<int32_t>();
    {
        MessageParcel data;
        MovieSettingsBlockMarshalling(data, movieSettings);
        MovieSettingsBlockUnmarshalling(data, movieSettings);
    }

    OutputInfo outputInfo;
    outputInfo.type = static_cast<OutputType>(fdp.ConsumeIntegral<int32_t>());
    outputInfo.minfps = fdp.ConsumeIntegral<int32_t>();
    outputInfo.maxfps = fdp.ConsumeIntegral<int32_t>();
    outputInfo.width = fdp.ConsumeIntegral<int32_t>();
    outputInfo.height = fdp.ConsumeIntegral<int32_t>();
    {
        MessageParcel data;
        OutputInfoBlockMarshalling(data, outputInfo);
        OutputInfoBlockUnmarshalling(data, outputInfo);
    }

    ZoomInfo zoomInfo;
    zoomInfo.zoomValue = fdp.ConsumeFloatingPoint<float>();
    zoomInfo.equivalentFocus = fdp.ConsumeIntegral<int32_t>();
    zoomInfo.focusStatus = fdp.ConsumeBool();
    zoomInfo.focusMode = fdp.ConsumeIntegral<int32_t>();
    zoomInfo.videoStabilizationMode = fdp.ConsumeIntegral<int32_t>();
    {
        MessageParcel data;
        ZoomInfoBlockMarshalling(data, zoomInfo);
        ZoomInfoBlockUnmarshalling(data, zoomInfo);
    }

    CameraStatusData cameraStatusData;
    cameraStatusData.cameraId = fdp.ConsumeRandomLengthString(NUM_10);
    cameraStatusData.cameraStatus = fdp.ConsumeIntegral<int32_t>();
    cameraStatusData.flashStatus = fdp.ConsumeIntegral<int32_t>();
    {
        MessageParcel data;
        CameraStatusDataBlockMarshalling(data, cameraStatusData);
        CameraStatusDataBlockUnmarshalling(data, cameraStatusData);
    }

    dmDeviceInfo dmdeviceInfo;
    dmdeviceInfo.deviceName = fdp.ConsumeRandomLengthString(NUM_10);
    dmdeviceInfo.deviceTypeId = fdp.ConsumeIntegral<int32_t>();
    dmdeviceInfo.networkId = fdp.ConsumeRandomLengthString(NUM_10);
    {
        MessageParcel data;
        dmDeviceInfoBlockMarshalling(data, dmdeviceInfo);
        dmDeviceInfoBlockUnmarshalling(data, dmdeviceInfo);
    }

    CallerDeviceInfo callerDeviceInfo;
    callerDeviceInfo.deviceId = fdp.ConsumeRandomLengthString(NUM_10);
    callerDeviceInfo.deviceName = fdp.ConsumeRandomLengthString(NUM_10);
    {
        MessageParcel data;
        CallerDeviceInfoBlockMarshalling(data, callerDeviceInfo);
        CallerDeviceInfoBlockUnmarshalling(data, callerDeviceInfo);
    }
}

void CameraTypesFuzz::TestComplexTypes(FuzzedDataProvider& fdp)
{
    CaptureSessionInfo captureSessionInfo;
    captureSessionInfo.sessionId = fdp.ConsumeIntegral<int32_t>();
    captureSessionInfo.callerTokenId = fdp.ConsumeIntegral<int32_t>();
    captureSessionInfo.cameraId = fdp.ConsumeRandomLengthString(NUM_10);
    captureSessionInfo.position = fdp.ConsumeIntegral<int32_t>();
    captureSessionInfo.sessionMode = fdp.ConsumeIntegral<int32_t>();
    uint8_t outputSize = fdp.ConsumeIntegralInRange<uint8_t>(0, MAX_BUFFER_SIZE);
    for (int i = 0; i < outputSize; ++i) {
        OutputInfo outputInfo;
        outputInfo.type = static_cast<OutputType>(fdp.ConsumeIntegral<int32_t>());
        outputInfo.minfps = fdp.ConsumeIntegral<int32_t>();
        outputInfo.maxfps = fdp.ConsumeIntegral<int32_t>();
        outputInfo.width = fdp.ConsumeIntegral<int32_t>();
        outputInfo.height = fdp.ConsumeIntegral<int32_t>();
        captureSessionInfo.outputInfos.push_back(outputInfo);
    }
    captureSessionInfo.colorSpace = fdp.ConsumeIntegral<int32_t>();
    captureSessionInfo.zoomInfo.zoomValue = fdp.ConsumeFloatingPoint<float>();
    captureSessionInfo.zoomInfo.equivalentFocus = fdp.ConsumeIntegral<int32_t>();
    captureSessionInfo.zoomInfo.focusStatus = fdp.ConsumeBool();
    captureSessionInfo.zoomInfo.focusMode = fdp.ConsumeIntegral<int32_t>();
    captureSessionInfo.zoomInfo.videoStabilizationMode = fdp.ConsumeIntegral<int32_t>();
    captureSessionInfo.sessionStatus = fdp.ConsumeBool();
    {
        MessageParcel data;
        CaptureSessionInfoBlockMarshalling(data, captureSessionInfo);
        CaptureSessionInfoBlockUnmarshalling(data, captureSessionInfo);
    }
}

void CameraTypesFuzz::TestErrorCases(FuzzedDataProvider& fdp)
{
    EffectParam effectParam;
    {
        MessageParcel data;
        data.WriteInt32(123);
        EffectParamBlockUnmarshalling(data, effectParam);
    }

    SketchStatusData sketchStatusData;
    {
        MessageParcel data;
        data.WriteInt32(456);
        SketchStatusDataBlockUnmarshalling(data, sketchStatusData);
    }

    CaptureEndedInfoExt captureEndedInfoExt;
    {
        MessageParcel data;
        data.WriteInt32(789);
        CaptureEndedInfoExtBlockUnmarshalling(data, captureEndedInfoExt);
    }

    ControlCenterStatusInfo controlCenterStatusInfo;
    {
        MessageParcel data;
        data.WriteInt32(999);
        ControlCenterStatusInfoBlockUnmarshalling(data, controlCenterStatusInfo);
    }

    IpcVideoProfile ipcVideoProfile;
    {
        MessageParcel data;
        data.WriteInt32(111);
        IpcVideoProfileBlockUnmarshalling(data, ipcVideoProfile);
    }

    Location location;
    {
        MessageParcel data;
        data.WriteInt32(222);
        LocationBlockUnmarshalling(data, location);
    }

    MovieSettings movieSettings;
    {
        MessageParcel data;
        data.WriteInt32(333);
        MovieSettingsBlockUnmarshalling(data, movieSettings);
    }

    OutputInfo outputInfo;
    {
        MessageParcel data;
        data.WriteInt32(444);
        OutputInfoBlockUnmarshalling(data, outputInfo);
    }

    ZoomInfo zoomInfo;
    {
        MessageParcel data;
        data.WriteInt32(555);
        ZoomInfoBlockUnmarshalling(data, zoomInfo);
    }

    CaptureSessionInfo captureSessionInfo;
    {
        MessageParcel data;
        data.WriteInt32(666);
        CaptureSessionInfoBlockUnmarshalling(data, captureSessionInfo);
    }

    CameraStatusData cameraStatusData;
    {
        MessageParcel data;
        data.WriteInt32(777);
        CameraStatusDataBlockUnmarshalling(data, cameraStatusData);
    }

    dmDeviceInfo dmdeviceInfo;
    {
        MessageParcel data;
        data.WriteInt32(17000);
        dmDeviceInfoBlockUnmarshalling(data, dmdeviceInfo);
    }

    CallerDeviceInfo callerDeviceInfo;
    {
        MessageParcel data;
        data.WriteInt32(18000);
        CallerDeviceInfoBlockUnmarshalling(data, callerDeviceInfo);
    }
}

void FuzzTest(const uint8_t* rawData, size_t size)
{
    FuzzedDataProvider fdp(rawData, size);
    auto cameraTypes = std::make_unique<CameraTypesFuzz>();
    if (cameraTypes == nullptr) {
        MEDIA_INFO_LOG("cameraTypes is null");
        return;
    }
    cameraTypes->CameraTypesFuzzTest(fdp);
}

} // namespace CameraStandard
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size)
{
    OHOS::CameraStandard::FuzzTest(data, size);
    return 0;
}