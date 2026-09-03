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
static constexpr int32_t NUM_5 = 5;
static constexpr int32_t NUM_111 = 111;
static constexpr int32_t NUM_123 = 123;
static constexpr int32_t NUM_222 = 222;
static constexpr int32_t NUM_333 = 333;
static constexpr int32_t NUM_444 = 444;
static constexpr int32_t NUM_456 = 456;
static constexpr int32_t NUM_555 = 555;
static constexpr int32_t NUM_666 = 666;
static constexpr int32_t NUM_777 = 777;
static constexpr int32_t NUM_789 = 789;
static constexpr int32_t NUM_888 = 888;
static constexpr int32_t NUM_999 = 999;
static constexpr int32_t NUM_1000 = 1000;
static constexpr int32_t NUM_2000 = 2000;
static constexpr int32_t NUM_3000 = 3000;
static constexpr int32_t NUM_4000 = 4000;
static constexpr int32_t NUM_5000 = 5000;
static constexpr int32_t NUM_6000 = 6000;
static constexpr int32_t NUM_7000 = 7000;
static constexpr int32_t NUM_8000 = 8000;
static constexpr int32_t NUM_9000 = 9000;
static constexpr int32_t NUM_11000 = 11000;
static constexpr int32_t NUM_12000 = 12000;
static constexpr int32_t NUM_13000 = 13000;
static constexpr int32_t NUM_14000 = 14000;
static constexpr int32_t NUM_15000 = 15000;
static constexpr int32_t NUM_16000 = 16000;
static constexpr int32_t NUM_17000 = 17000;
static constexpr int32_t NUM_18000 = 18000;
static constexpr int32_t NUM_10000 = 10000;

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
    movieSettings.isRotationSet = fdp.ConsumeBool();
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

    BaseFeatureInfo baseFeatureInfo;
    baseFeatureInfo.featureId = static_cast<FeatureId>(fdp.ConsumeIntegral<int32_t>());
    {
        MessageParcel data;
        BaseFeatureInfoBlockMarshalling(data, baseFeatureInfo);
        BaseFeatureInfoBlockUnmarshalling(data, baseFeatureInfo);
    }

    ReqCallerInfo reqCallerInfo;
    reqCallerInfo.bundleName = fdp.ConsumeRandomLengthString(NUM_10);
    {
        MessageParcel data;
        ReqCallerInfoBlockMarshalling(data, reqCallerInfo);
        ReqCallerInfoBlockUnmarshalling(data, reqCallerInfo);
    }

    BaseResult baseResult;
    baseResult.resCode = fdp.ConsumeIntegral<int32_t>();
    baseResult.resMsg = fdp.ConsumeRandomLengthString(NUM_10);
    {
        MessageParcel data;
        BaseResultBlockMarshalling(data, baseResult);
        BaseResultBlockUnmarshalling(data, baseResult);
    }

    DeletePredicates deletePredicates;
    deletePredicates.downloadedDuration = fdp.ConsumeIntegral<int32_t>();
    {
        MessageParcel data;
        DeletePredicatesBlockMarshalling(data, deletePredicates);
        DeletePredicatesBlockUnmarshalling(data, deletePredicates);
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

static void TestCaptureSessionInfo(FuzzedDataProvider& fdp)
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

static void TestRequestBodyParams(FuzzedDataProvider& fdp)
{
    RequestBodyParams requestBodyParams;
    requestBodyParams.callerInfo.bundleName = fdp.ConsumeRandomLengthString(NUM_10);
    requestBodyParams.featureId = static_cast<FeatureId>(fdp.ConsumeIntegral<int32_t>());
    requestBodyParams.typeId = static_cast<TypeId>(fdp.ConsumeIntegral<int32_t>());
    requestBodyParams.templateId = fdp.ConsumeIntegral<int32_t>();
    requestBodyParams.resourceId = fdp.ConsumeIntegral<int32_t>();
    requestBodyParams.packageType = static_cast<PackageType>(fdp.ConsumeIntegral<int32_t>());
    MessageParcel data;
    RequestBodyParamsBlockMarshalling(data, requestBodyParams);
    RequestBodyParamsBlockUnmarshalling(data, requestBodyParams);
}

static ResourceInfo TestResourceInfo(FuzzedDataProvider& fdp)
{
    ResourceInfo resourceInfo;
    resourceInfo.resourceId = fdp.ConsumeIntegral<int32_t>();
    resourceInfo.fullResourceId = fdp.ConsumeIntegral<int32_t>();
    resourceInfo.templateId = fdp.ConsumeIntegral<int32_t>();
    resourceInfo.typeId = static_cast<TypeId>(fdp.ConsumeIntegral<int32_t>());
    resourceInfo.effectiveTime = fdp.ConsumeRandomLengthString(NUM_10);
    resourceInfo.expirationTime = fdp.ConsumeRandomLengthString(NUM_10);
    uint8_t coverUriSize = fdp.ConsumeIntegralInRange<uint8_t>(0, MAX_BUFFER_SIZE);
    for (int i = 0; i < coverUriSize; ++i) {
        resourceInfo.coverUriForCamera.push_back(fdp.ConsumeRandomLengthString(NUM_5));
    }
    resourceInfo.coverUriForPhotoGallery = fdp.ConsumeRandomLengthString(NUM_10);
    resourceInfo.resourceDownloadStatus = static_cast<ResourceDownloadStatus>(fdp.ConsumeIntegral<int32_t>());
    resourceInfo.fullRomSize = fdp.ConsumeIntegral<int32_t>();
    resourceInfo.isVideoSupported = fdp.ConsumeBool();
    resourceInfo.resourcePriority = fdp.ConsumeIntegral<int32_t>();
    resourceInfo.typePriority = fdp.ConsumeIntegral<int32_t>();
    MessageParcel data;
    ResourceInfoBlockMarshalling(data, resourceInfo);
    ResourceInfoBlockUnmarshalling(data, resourceInfo);
    return resourceInfo;
}

static void TestTemplateTypes(FuzzedDataProvider& fdp)
{
    Selector selector;
    selector.id = fdp.ConsumeIntegral<int32_t>();
    selector.type = static_cast<SelectorType>(fdp.ConsumeIntegral<int32_t>());
    selector.shapeType = static_cast<ShapeType>(fdp.ConsumeIntegral<int32_t>());
    uint8_t textColorSize = fdp.ConsumeIntegralInRange<uint8_t>(0, MAX_BUFFER_SIZE);
    for (int i = 0; i < textColorSize; ++i) {
        selector.textColor.push_back(fdp.ConsumeRandomLengthString(NUM_5));
    }
    uint8_t sourceSize = fdp.ConsumeIntegralInRange<uint8_t>(0, MAX_BUFFER_SIZE);
    for (int i = 0; i < sourceSize; ++i) {
        selector.source.push_back(fdp.ConsumeRandomLengthString(NUM_5));
    }
    uint8_t previewSourceSize = fdp.ConsumeIntegralInRange<uint8_t>(0, MAX_BUFFER_SIZE);
    for (int i = 0; i < previewSourceSize; ++i) {
        selector.previewSource.push_back(fdp.ConsumeRandomLengthString(NUM_5));
    }
    {
        MessageParcel data;
        SelectorBlockMarshalling(data, selector);
        SelectorBlockUnmarshalling(data, selector);
    }

    DefaultValue defaultValue;
    defaultValue.switcher = fdp.ConsumeBool();
    defaultValue.selector = fdp.ConsumeIntegral<int32_t>();
    defaultValue.custom = fdp.ConsumeRandomLengthString(NUM_10);
    {
        MessageParcel data;
        DefaultValueBlockMarshalling(data, defaultValue);
        DefaultValueBlockUnmarshalling(data, defaultValue);
    }

    ParamInfo paramInfo;
    paramInfo.paramId = fdp.ConsumeRandomLengthString(NUM_10);
    paramInfo.defaultValue.switcher = fdp.ConsumeBool();
    paramInfo.defaultValue.selector = fdp.ConsumeIntegral<int32_t>();
    paramInfo.defaultValue.custom = fdp.ConsumeRandomLengthString(NUM_10);
    paramInfo.titleText = fdp.ConsumeRandomLengthString(NUM_10);
    paramInfo.type = static_cast<ParamType>(fdp.ConsumeIntegral<int32_t>());
    paramInfo.description = fdp.ConsumeRandomLengthString(NUM_10);
    uint8_t selectorSize = fdp.ConsumeIntegralInRange<uint8_t>(0, MAX_BUFFER_SIZE);
    for (int i = 0; i < selectorSize; ++i) {
        Selector sel;
        sel.id = fdp.ConsumeIntegral<int32_t>();
        sel.type = static_cast<SelectorType>(fdp.ConsumeIntegral<int32_t>());
        sel.shapeType = static_cast<ShapeType>(fdp.ConsumeIntegral<int32_t>());
        paramInfo.selectors.push_back(sel);
    }
    paramInfo.affectedField = fdp.ConsumeRandomLengthString(NUM_10);
    paramInfo.isVideoSupported = fdp.ConsumeBool();
    paramInfo.isShow= fdp.ConsumeBool();
    {
        MessageParcel data;
        ParamInfoBlockMarshalling(data, paramInfo);
        ParamInfoBlockUnmarshalling(data, paramInfo);
    }

    DetailTemplateInfo detailTemplateInfo;
    detailTemplateInfo.resourceId = fdp.ConsumeIntegral<int32_t>();
    detailTemplateInfo.fullResourceId = fdp.ConsumeIntegral<int32_t>();
    detailTemplateInfo.templateId = fdp.ConsumeIntegral<int32_t>();
    detailTemplateInfo.typeId = static_cast<TypeId>(fdp.ConsumeIntegral<int32_t>());
    detailTemplateInfo.effectiveTime = fdp.ConsumeRandomLengthString(NUM_10);
    detailTemplateInfo.expirationTime = fdp.ConsumeRandomLengthString(NUM_10);
    uint8_t coverUriSize2 = fdp.ConsumeIntegralInRange<uint8_t>(0, MAX_BUFFER_SIZE);
    for (int i = 0; i < coverUriSize2; ++i) {
        detailTemplateInfo.coverUriForCamera.push_back(fdp.ConsumeRandomLengthString(NUM_5));
    }
    detailTemplateInfo.coverUriForPhotoGallery = fdp.ConsumeRandomLengthString(NUM_10);
    detailTemplateInfo.resourceDownloadStatus = static_cast<ResourceDownloadStatus>(fdp.ConsumeIntegral<int32_t>());
    detailTemplateInfo.fullRomSize = fdp.ConsumeIntegral<int32_t>();
    detailTemplateInfo.isVideoSupported = fdp.ConsumeBool();
    detailTemplateInfo.resourcePriority = fdp.ConsumeIntegral<int32_t>();
    detailTemplateInfo.typePriority = fdp.ConsumeIntegral<int32_t>();
    uint8_t paramListSize = fdp.ConsumeIntegralInRange<uint8_t>(0, MAX_BUFFER_SIZE);
    for (int i = 0; i < paramListSize; ++i) {
        ParamInfo pInfo;
        pInfo.paramId = fdp.ConsumeRandomLengthString(NUM_5);
        pInfo.type = static_cast<ParamType>(fdp.ConsumeIntegral<int32_t>());
        detailTemplateInfo.paramList.push_back(pInfo);
    }
    {
        MessageParcel data;
        DetailTemplateInfoBlockMarshalling(data, detailTemplateInfo);
        DetailTemplateInfoBlockUnmarshalling(data, detailTemplateInfo);
    }
}

static void TestResultTypes(FuzzedDataProvider& fdp)
{
    TypeInfo typeInfo;
    typeInfo.typeId = static_cast<TypeId>(fdp.ConsumeIntegral<int32_t>());
    uint8_t infosSize = fdp.ConsumeIntegralInRange<uint8_t>(0, MAX_BUFFER_SIZE);
    for (int i = 0; i < infosSize; ++i) {
        ResourceInfo rInfo;
        rInfo.resourceId = fdp.ConsumeIntegral<int32_t>();
        rInfo.typeId = static_cast<TypeId>(fdp.ConsumeIntegral<int32_t>());
        typeInfo.infos.push_back(rInfo);
    }
    {
        MessageParcel data;
        TypeInfoBlockMarshalling(data, typeInfo);
        TypeInfoBlockUnmarshalling(data, typeInfo);
    }

    DetailTypeInfo detailTypeInfo;
    detailTypeInfo.typeId = static_cast<TypeId>(fdp.ConsumeIntegral<int32_t>());
    uint8_t detailInfosSize = fdp.ConsumeIntegralInRange<uint8_t>(0, MAX_BUFFER_SIZE);
    for (int i = 0; i < detailInfosSize; ++i) {
        DetailTemplateInfo dtInfo;
        dtInfo.resourceId = fdp.ConsumeIntegral<int32_t>();
        dtInfo.typeId = static_cast<TypeId>(fdp.ConsumeIntegral<int32_t>());
        detailTypeInfo.infos.push_back(dtInfo);
    }
    {
        MessageParcel data;
        DetailTypeInfoBlockMarshalling(data, detailTypeInfo);
        DetailTypeInfoBlockUnmarshalling(data, detailTypeInfo);
    }

    PostureResourceInfo postureResourceInfo;
    postureResourceInfo.featureId = fdp.ConsumeIntegral<int32_t>();
    postureResourceInfo.resourceId = fdp.ConsumeIntegral<int32_t>();
    postureResourceInfo.resourceDownloadStatus = static_cast<ResourceDownloadStatus>(fdp.ConsumeIntegral<int32_t>());
    postureResourceInfo.fullRomSize = fdp.ConsumeIntegral<int32_t>();
    postureResourceInfo.poseVersion = fdp.ConsumeRandomLengthString(NUM_10);
    {
        MessageParcel data;
        PostureResourceInfoBlockMarshalling(data, postureResourceInfo);
        PostureResourceInfoBlockUnmarshalling(data, postureResourceInfo);
    }

    PostureTypeInfo postureTypeInfo;
    postureTypeInfo.typeId = static_cast<TypeId>(fdp.ConsumeIntegral<int32_t>());
    uint8_t postureInfosSize = fdp.ConsumeIntegralInRange<uint8_t>(0, MAX_BUFFER_SIZE);
    for (int i = 0; i < postureInfosSize; ++i) {
        PostureResourceInfo prInfo;
        prInfo.featureId = fdp.ConsumeIntegral<int32_t>();
        prInfo.resourceId = fdp.ConsumeIntegral<int32_t>();
        postureTypeInfo.infos.push_back(prInfo);
    }
    {
        MessageParcel data;
        PostureTypeInfoBlockMarshalling(data, postureTypeInfo);
        PostureTypeInfoBlockUnmarshalling(data, postureTypeInfo);
    }

    BaseResult baseResult;
    baseResult.resCode = fdp.ConsumeIntegral<int32_t>();
    baseResult.resMsg = fdp.ConsumeRandomLengthString(NUM_10);
    {
        MessageParcel data;
        BaseResultBlockMarshalling(data, baseResult);
        BaseResultBlockUnmarshalling(data, baseResult);
    }

    FeatureResult featureResult;
    featureResult.resCode = fdp.ConsumeIntegral<int32_t>();
    featureResult.resMsg = fdp.ConsumeRandomLengthString(NUM_10);
    uint8_t featureInfosSize = fdp.ConsumeIntegralInRange<uint8_t>(0, MAX_BUFFER_SIZE);
    for (int i = 0; i < featureInfosSize; ++i) {
        TypeInfo tInfo;
        tInfo.typeId = static_cast<TypeId>(fdp.ConsumeIntegral<int32_t>());
        featureResult.featureInfos.push_back(tInfo);
    }
    {
        MessageParcel data;
        FeatureResultBlockMarshalling(data, featureResult);
        FeatureResultBlockUnmarshalling(data, featureResult);
    }

    DetailFeatureResult detailFeatureResult;
    detailFeatureResult.resCode = fdp.ConsumeIntegral<int32_t>();
    detailFeatureResult.resMsg = fdp.ConsumeRandomLengthString(NUM_10);
    uint8_t detailFeatureInfosSize = fdp.ConsumeIntegralInRange<uint8_t>(0, MAX_BUFFER_SIZE);
    for (int i = 0; i < detailFeatureInfosSize; ++i) {
        DetailTypeInfo dtInfo;
        dtInfo.typeId = static_cast<TypeId>(fdp.ConsumeIntegral<int32_t>());
        detailFeatureResult.featureInfos.push_back(dtInfo);
    }
    {
        MessageParcel data;
        DetailFeatureResultBlockMarshalling(data, detailFeatureResult);
        DetailFeatureResultBlockUnmarshalling(data, detailFeatureResult);
    }

    PostureResult postureResult;
    postureResult.resCode = fdp.ConsumeIntegral<int32_t>();
    postureResult.resMsg = fdp.ConsumeRandomLengthString(NUM_10);
    uint8_t postureFeatureInfosSize = fdp.ConsumeIntegralInRange<uint8_t>(0, MAX_BUFFER_SIZE);
    for (int i = 0; i < postureFeatureInfosSize; ++i) {
        PostureTypeInfo ptInfo;
        ptInfo.typeId = static_cast<TypeId>(fdp.ConsumeIntegral<int32_t>());
        postureResult.featureInfos.push_back(ptInfo);
    }
    {
        MessageParcel data;
        PostureResultBlockMarshalling(data, postureResult);
        PostureResultBlockUnmarshalling(data, postureResult);
    }

    DeletePredicates deletePredicates;
    deletePredicates.downloadedDuration = fdp.ConsumeIntegral<int32_t>();
    {
        MessageParcel data;
        DeletePredicatesBlockMarshalling(data, deletePredicates);
        DeletePredicatesBlockUnmarshalling(data, deletePredicates);
    }

    WatermarkResultContainer watermarkResultContainer;
    watermarkResultContainer.resultType = static_cast<ResultType>(fdp.ConsumeIntegral<int32_t>());
    watermarkResultContainer.featureResult.resCode = fdp.ConsumeIntegral<int32_t>();
    watermarkResultContainer.featureResult.resMsg = fdp.ConsumeRandomLengthString(NUM_10);
    watermarkResultContainer.detailFeatureResult.resCode = fdp.ConsumeIntegral<int32_t>();
    watermarkResultContainer.detailFeatureResult.resMsg = fdp.ConsumeRandomLengthString(NUM_10);
    watermarkResultContainer.postureResult.resCode = fdp.ConsumeIntegral<int32_t>();
    watermarkResultContainer.postureResult.resMsg = fdp.ConsumeRandomLengthString(NUM_10);
    {
        MessageParcel data;
        WatermarkResultContainerBlockMarshalling(data, watermarkResultContainer);
        WatermarkResultContainerBlockUnmarshalling(data, watermarkResultContainer);
    }
}

static void TestRepeatedTypes(FuzzedDataProvider& fdp, ResourceInfo& resourceInfo)
{
    resourceInfo.coverUriForPhotoGallery = fdp.ConsumeRandomLengthString(NUM_10);
    resourceInfo.resourceDownloadStatus = static_cast<ResourceDownloadStatus>(fdp.ConsumeIntegral<int32_t>());
    resourceInfo.fullRomSize = fdp.ConsumeIntegral<int32_t>();
    resourceInfo.isVideoSupported = fdp.ConsumeBool();
    resourceInfo.resourcePriority = fdp.ConsumeIntegral<int32_t>();
    resourceInfo.typePriority = fdp.ConsumeIntegral<int32_t>();
    {
        MessageParcel data;
        ResourceInfoBlockMarshalling(data, resourceInfo);
        ResourceInfoBlockUnmarshalling(data, resourceInfo);
    }

    Selector selector;
    selector.id = fdp.ConsumeIntegral<int32_t>();
    selector.type = static_cast<SelectorType>(fdp.ConsumeIntegral<int32_t>());
    selector.shapeType = static_cast<ShapeType>(fdp.ConsumeIntegral<int32_t>());
    uint8_t nestedTextColorSize = fdp.ConsumeIntegralInRange<uint8_t>(0, MAX_BUFFER_SIZE);
    for (int i = 0; i < nestedTextColorSize; ++i) {
        selector.textColor.push_back(fdp.ConsumeRandomLengthString(NUM_5));
    }
    uint8_t nestedSourceSize = fdp.ConsumeIntegralInRange<uint8_t>(0, MAX_BUFFER_SIZE);
    for (int i = 0; i < nestedSourceSize; ++i) {
        selector.source.push_back(fdp.ConsumeRandomLengthString(NUM_5));
    }
    uint8_t nestedPreviewSourceSize = fdp.ConsumeIntegralInRange<uint8_t>(0, MAX_BUFFER_SIZE);
    for (int i = 0; i < nestedPreviewSourceSize; ++i) {
        selector.previewSource.push_back(fdp.ConsumeRandomLengthString(NUM_5));
    }
    {
        MessageParcel data;
        SelectorBlockMarshalling(data, selector);
        SelectorBlockUnmarshalling(data, selector);
    }
}

void CameraTypesFuzz::TestComplexTypes(FuzzedDataProvider& fdp)
{
    TestCaptureSessionInfo(fdp);

    TestRequestBodyParams(fdp);
    ResourceInfo resourceInfo = TestResourceInfo(fdp);
    TestTemplateTypes(fdp);
    TestResultTypes(fdp);
    TestRepeatedTypes(fdp, resourceInfo);
}

void CameraTypesFuzz::TestErrorCases(FuzzedDataProvider& fdp)
{
    EffectParam effectParam;
    {
        MessageParcel data;
        data.WriteInt32(NUM_123);
        EffectParamBlockUnmarshalling(data, effectParam);
    }

    SketchStatusData sketchStatusData;
    {
        MessageParcel data;
        data.WriteInt32(NUM_456);
        SketchStatusDataBlockUnmarshalling(data, sketchStatusData);
    }

    CaptureEndedInfoExt captureEndedInfoExt;
    {
        MessageParcel data;
        data.WriteInt32(NUM_789);
        CaptureEndedInfoExtBlockUnmarshalling(data, captureEndedInfoExt);
    }

    ControlCenterStatusInfo controlCenterStatusInfo;
    {
        MessageParcel data;
        data.WriteInt32(NUM_999);
        ControlCenterStatusInfoBlockUnmarshalling(data, controlCenterStatusInfo);
    }

    IpcVideoProfile ipcVideoProfile;
    {
        MessageParcel data;
        data.WriteInt32(NUM_111);
        IpcVideoProfileBlockUnmarshalling(data, ipcVideoProfile);
    }

    Location location;
    {
        MessageParcel data;
        data.WriteInt32(NUM_222);
        LocationBlockUnmarshalling(data, location);
    }

    MovieSettings movieSettings;
    {
        MessageParcel data;
        data.WriteInt32(NUM_333);
        MovieSettingsBlockUnmarshalling(data, movieSettings);
    }

    OutputInfo outputInfo;
    {
        MessageParcel data;
        data.WriteInt32(NUM_444);
        OutputInfoBlockUnmarshalling(data, outputInfo);
    }

    ZoomInfo zoomInfo;
    {
        MessageParcel data;
        data.WriteInt32(NUM_555);
        ZoomInfoBlockUnmarshalling(data, zoomInfo);
    }

    CaptureSessionInfo captureSessionInfo;
    {
        MessageParcel data;
        data.WriteInt32(NUM_666);
        CaptureSessionInfoBlockUnmarshalling(data, captureSessionInfo);
    }

    CameraStatusData cameraStatusData;
    {
        MessageParcel data;
        data.WriteInt32(NUM_777);
        CameraStatusDataBlockUnmarshalling(data, cameraStatusData);
    }

    BaseFeatureInfo baseFeatureInfo;
    {
        MessageParcel data;
        data.WriteInt32(NUM_888);
        BaseFeatureInfoBlockUnmarshalling(data, baseFeatureInfo);
    }

    ReqCallerInfo reqCallerInfo;
    {
        MessageParcel data;
        data.WriteInt32(NUM_999);
        ReqCallerInfoBlockUnmarshalling(data, reqCallerInfo);
    }

    RequestBodyParams requestBodyParams;
    {
        MessageParcel data;
        data.WriteInt32(NUM_1000);
        RequestBodyParamsBlockUnmarshalling(data, requestBodyParams);
    }

    ResourceInfo resourceInfo;
    {
        MessageParcel data;
        data.WriteInt32(NUM_2000);
        ResourceInfoBlockUnmarshalling(data, resourceInfo);
    }

    Selector selector;
    {
        MessageParcel data;
        data.WriteInt32(NUM_3000);
        SelectorBlockUnmarshalling(data, selector);
    }

    DefaultValue defaultValue;
    {
        MessageParcel data;
        data.WriteInt32(NUM_4000);
        DefaultValueBlockUnmarshalling(data, defaultValue);
    }

    ParamInfo paramInfo;
    {
        MessageParcel data;
        data.WriteInt32(NUM_5000);
        ParamInfoBlockUnmarshalling(data, paramInfo);
    }

    DetailTemplateInfo detailTemplateInfo;
    {
        MessageParcel data;
        data.WriteInt32(NUM_6000);
        DetailTemplateInfoBlockUnmarshalling(data, detailTemplateInfo);
    }

    TypeInfo typeInfo;
    {
        MessageParcel data;
        data.WriteInt32(NUM_7000);
        TypeInfoBlockUnmarshalling(data, typeInfo);
    }

    DetailTypeInfo detailTypeInfo;
    {
        MessageParcel data;
        data.WriteInt32(NUM_8000);
        DetailTypeInfoBlockUnmarshalling(data, detailTypeInfo);
    }

    PostureResourceInfo postureResourceInfo;
    {
        MessageParcel data;
        data.WriteInt32(NUM_9000);
        PostureResourceInfoBlockUnmarshalling(data, postureResourceInfo);
    }

    PostureTypeInfo postureTypeInfo;
    {
        MessageParcel data;
        data.WriteInt32(NUM_10000);
        PostureTypeInfoBlockUnmarshalling(data, postureTypeInfo);
    }

    BaseResult baseResult;
    {
        MessageParcel data;
        data.WriteInt32(NUM_11000);
        BaseResultBlockUnmarshalling(data, baseResult);
    }

    FeatureResult featureResult;
    {
        MessageParcel data;
        data.WriteInt32(NUM_12000);
        FeatureResultBlockUnmarshalling(data, featureResult);
    }

    DetailFeatureResult detailFeatureResult;
    {
        MessageParcel data;
        data.WriteInt32(NUM_13000);
        DetailFeatureResultBlockUnmarshalling(data, detailFeatureResult);
    }

    PostureResult postureResult;
    {
        MessageParcel data;
        data.WriteInt32(NUM_14000);
        PostureResultBlockUnmarshalling(data, postureResult);
    }

    DeletePredicates deletePredicates;
    {
        MessageParcel data;
        data.WriteInt32(NUM_15000);
        DeletePredicatesBlockUnmarshalling(data, deletePredicates);
    }

    WatermarkResultContainer watermarkResultContainer;
    {
        MessageParcel data;
        data.WriteInt32(NUM_16000);
        WatermarkResultContainerBlockUnmarshalling(data, watermarkResultContainer);
    }

    dmDeviceInfo dmdeviceInfo;
    {
        MessageParcel data;
        data.WriteInt32(NUM_17000);
        dmDeviceInfoBlockUnmarshalling(data, dmdeviceInfo);
    }

    CallerDeviceInfo callerDeviceInfo;
    {
        MessageParcel data;
        data.WriteInt32(NUM_18000);
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