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

#include "hstream_capture_fuzzer.h"
#include "camera_log.h"
#include "message_parcel.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"
#include <cstddef>
#include <cstdint>
#include <memory>
#include "token_setproc.h"
#include "iconsumer_surface.h"
#include "nativetoken_kit.h"
#include "accesstoken_kit.h"
#include "camera_metadata_info.h"
#include "metadata_utils.h"
#include "camera_device.h"
#include "camera_manager.h"
#include "ipc_skeleton.h"
#include "securec.h"
#include <fuzzer/FuzzedDataProvider.h>
#include "test_token.h"

using namespace OHOS::CameraStandard;
using namespace OHOS::HDI::Camera::V1_0;
const size_t MAX_LENGTH_STRING = 64;
const int32_t PHOTO_WIDTH = 1280;
const int32_t PHOTO_HEIGHT = 960;
const int32_t PHOTO_FORMAT = 2000;
const int32_t ITEMCOUNT = 10;
const int32_t DATASIZE = 100;
const uint32_t MAX_AUX_PHOTO_TYPE_COUNT = 3;

static sptr<IBufferProducer> g_producer;
static sptr<Surface> g_photoSurface;
static sptr<SurfaceBuffer> g_auxPhotoProxyBuffer;

static HStreamCapture& GetInstance()
{
    static HStreamCapture hStreamCapture(g_producer, PHOTO_FORMAT, PHOTO_WIDTH, PHOTO_HEIGHT);
    return hStreamCapture;
}

sptr<IBufferProducer> GetMockBufferProducer()
{
    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    if (!surface) {
        return nullptr;
    }
    return surface->GetProducer();
}

void Capture(FuzzedDataProvider& fdp)
{
    auto captureSettings = std::make_shared<OHOS::Camera::CameraMetadata>(
        fdp.ConsumeIntegralInRange(0, ITEMCOUNT), fdp.ConsumeIntegralInRange(0, DATASIZE));
    GetInstance().Capture(captureSettings);
}

void CancelCapture(FuzzedDataProvider& fdp)
{
    GetInstance().CancelCapture();
}

void SetCallback(FuzzedDataProvider& fdp)
{
    auto cb = sptr<MockStreamCaptureCallback>::MakeSptr();
    GetInstance().SetCallback(cb);
}

void Release(FuzzedDataProvider& fdp)
{
    GetInstance().Release();
}

void SetThumbnail(FuzzedDataProvider& fdp)
{
    GetInstance().SetThumbnail(fdp.ConsumeBool());
}

void ConfirmCapture(FuzzedDataProvider& fdp)
{
    GetInstance().ConfirmCapture();
}

void DeferImageDeliveryFor(FuzzedDataProvider& fdp)
{
    GetInstance().DeferImageDeliveryFor(fdp.ConsumeIntegral<int32_t>());
}

void IsDeferredPhotoEnabled(FuzzedDataProvider& fdp)
{
    GetInstance().IsDeferredPhotoEnabled();
}

void IsDeferredVideoEnabled(FuzzedDataProvider& fdp)
{
    GetInstance().IsDeferredVideoEnabled();
}

void SetBufferProducerInfo(FuzzedDataProvider& fdp)
{
    GetInstance().SetBufferProducerInfo(fdp.ConsumeRandomLengthString(), GetMockBufferProducer());
}

void SetMovingPhotoVideoCodecType(FuzzedDataProvider& fdp)
{
    GetInstance().SetMovingPhotoVideoCodecType(fdp.ConsumeIntegral<int32_t>());
}

void EnableRawDelivery(FuzzedDataProvider& fdp)
{
    GetInstance().EnableRawDelivery(fdp.ConsumeBool());
}

void SetCameraPhotoRotation(FuzzedDataProvider& fdp)
{
    GetInstance().SetCameraPhotoRotation(fdp.ConsumeBool());
}

void EnableMovingPhoto(FuzzedDataProvider& fdp)
{
    GetInstance().EnableMovingPhoto(fdp.ConsumeBool());
}

void UnSetCallback(FuzzedDataProvider& fdp)
{
    GetInstance().UnSetCallback();
}

void EnableOfflinePhoto(FuzzedDataProvider& fdp)
{
    GetInstance().EnableOfflinePhoto(fdp.ConsumeBool());
}

void SetPhotoAvailableCallback(FuzzedDataProvider& fdp)
{
    auto cb = sptr<MockStreamCapturePhotoCallback>::MakeSptr();
    GetInstance().SetPhotoAvailableCallback(cb);
}

void SetPhotoAssetAvailableCallback(FuzzedDataProvider& fdp)
{
    auto cb = sptr<MockStreamCapturePhotoAssetCallback>::MakeSptr();
    GetInstance().SetPhotoAssetAvailableCallback(cb);
}

void SetThumbnailCallback(FuzzedDataProvider& fdp)
{
    auto cb = sptr<MockStreamCaptureThumbnailCallback>::MakeSptr();
    GetInstance().SetThumbnailCallback(cb);
}

void UnSetPhotoAvailableCallback(FuzzedDataProvider& fdp)
{
    GetInstance().UnSetPhotoAssetAvailableCallback();
}

void UnSetPhotoAssetAvailableCallback(FuzzedDataProvider& fdp)
{
    GetInstance().UnSetPhotoAssetAvailableCallback();
}

void UnSetThumbnailCallback(FuzzedDataProvider& fdp)
{
    GetInstance().UnSetThumbnailCallback();
}

void CreateMediaLibrary(FuzzedDataProvider& fdp)
{
    auto photoProxy = sptr<CameraPhotoProxy>::MakeSptr();
    int32_t type = fdp.ConsumeIntegral<int32_t>();
    int64_t timestamp = fdp.ConsumeIntegral<int64_t>();
    std::string uri = fdp.ConsumeRandomLengthString();
    std::string burstKey = fdp.ConsumeRandomLengthString();
    GetInstance().CreateMediaLibrary(photoProxy, uri, type, burstKey, timestamp);
}

void SetAutoAuxiliaryPhotosDeliveryEnabled(FuzzedDataProvider& fdp)
{
    std::vector<int32_t> auxPhotoTypes;
    uint32_t auxPhotoTypeCount = fdp.ConsumeIntegralInRange<uint32_t>(0, MAX_AUX_PHOTO_TYPE_COUNT);
    for (uint32_t i = 0; i < auxPhotoTypeCount; i++) {
        auxPhotoTypes.push_back(fdp.ConsumeIntegralInRange<int32_t>(-1, 2));
    }
    GetInstance().SetAutoAuxiliaryPhotosDeliveryEnabled(auxPhotoTypes, fdp.ConsumeBool());
}

void AuxPhotoStateFuzzTest(FuzzedDataProvider& fdp)
{
    GetInstance().IsAuxPhotoEnabled();
    GetInstance().IsAuxPhotoDegraded(fdp.ConsumeIntegral<int32_t>());
    GetInstance().SendAuxiliaryPhotoControlTagIfDirty();
    GetInstance().CleanAuxPhotoState(fdp.ConsumeIntegral<int32_t>());
    StreamInfo_V1_5 streamInfo;
    GetInstance().SetStreamInfo(streamInfo);
}

void OnPhotoAvailableWithAuxiliary(FuzzedDataProvider& fdp)
{
    sptr<SurfaceBuffer> mainBuffer = fdp.ConsumeBool() ? SurfaceBuffer::Create() : nullptr;
    sptr<SurfaceBuffer> oxygenBuffer = fdp.ConsumeBool() ? SurfaceBuffer::Create() : nullptr;
    sptr<SurfaceBuffer> pigmentationBuffer = fdp.ConsumeBool() ? SurfaceBuffer::Create() : nullptr;
    GetInstance().OnPhotoAvailable(mainBuffer, oxygenBuffer, pigmentationBuffer,
        fdp.ConsumeIntegral<int64_t>(), fdp.ConsumeBool());
}

void OnPhotoAvailableWithAuxiliaryStub(FuzzedDataProvider& fdp)
{
    auto stub = sptr<MockStreamCapturePhotoCallback>::MakeSptr();
    CHECK_RETURN(stub == nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(stub->GetDescriptor());
    data.WriteBool(fdp.ConsumeBool());
    data.WriteBool(fdp.ConsumeBool());
    data.WriteBool(fdp.ConsumeBool());
    data.WriteInt64(fdp.ConsumeIntegral<int64_t>());
    data.WriteBool(fdp.ConsumeBool());
    stub->OnRemoteRequest(static_cast<uint32_t>(
        StreamCapturePhotoCallbackInterfaceCode::CAMERA_STREAM_CAPTURE_ON_PHOTO_AVAILABLE_WITH_AUXILIARY),
        data, reply, option);
}

void OnPhotoAvailableWithAuxiliaryProxy(FuzzedDataProvider& fdp)
{
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHECK_RETURN(samgr == nullptr);
    auto object = samgr->GetSystemAbility(CAMERA_SERVICE_ID);
    CHECK_RETURN(object == nullptr);
    auto proxy = iface_cast<IStreamCapturePhotoCallback>(object);
    CHECK_RETURN(proxy == nullptr);
    sptr<SurfaceBuffer> mainBuffer = fdp.ConsumeBool() ? g_auxPhotoProxyBuffer : nullptr;
    sptr<SurfaceBuffer> oxygenBuffer = fdp.ConsumeBool() ? g_auxPhotoProxyBuffer : nullptr;
    sptr<SurfaceBuffer> pigmentationBuffer = fdp.ConsumeBool() ? g_auxPhotoProxyBuffer : nullptr;
    proxy->OnPhotoAvailable(mainBuffer, oxygenBuffer, pigmentationBuffer,
        fdp.ConsumeIntegral<int64_t>(), fdp.ConsumeBool());
}

void StreamCaptureFuzzTest1(FuzzedDataProvider& fdp)
{
    int32_t captureId = fdp.ConsumeIntegral<int32_t>();
    bool isEnabled = fdp.ConsumeBool();
    bool enabled = fdp.ConsumeIntegral<bool>();
    GetInstance().CreateMediaLibraryPhotoAssetProxy(captureId);
    GetInstance().GetPhotoAssetInstance(captureId);
    GetInstance().GetAddPhotoProxyEnabled();
    GetInstance().AcquireBufferToPrepareProxy(captureId);
    StreamInfo_V1_5 streamInfo;
    GetInstance().SetStreamInfo(streamInfo);
    GetInstance().FillingPictureExtendStreamInfos(streamInfo, fdp.ConsumeIntegral<int32_t>());
    GetInstance().SetThumbnail(isEnabled);
    GetInstance().EnableRawDelivery(enabled);
    std::vector<std::string> bufferNames = { "rawImage", "gainmapImage", "deepImage", "exifImage", "debugImage" };
    for (const auto& bufName : bufferNames) {
        GetInstance().SetBufferProducerInfo(bufName, g_producer);
    }
    int32_t type = fdp.ConsumeIntegral<int32_t>();
    GetInstance().DeferImageDeliveryFor(type);
    GetInstance().PrepareBurst(captureId);
    GetInstance().ResetBurst();
    GetInstance().ResetBurstKey(captureId);
    GetInstance().GetBurstKey(captureId);
    GetInstance().IsBurstCapture(captureId);
    GetInstance().IsBurstCover(captureId);
    GetInstance().GetCurBurstSeq(captureId);
    GetInstance().IsDeferredPhotoEnabled();
    GetInstance().IsDeferredVideoEnabled();
    auto videoCodecType = fdp.ConsumeIntegral<int32_t>();
    GetInstance().SetMovingPhotoVideoCodecType(videoCodecType);
#ifdef CAMERA_MOVING_PHOTO
    GetInstance().GetMovingPhotoVideoCodecType();
#endif
    GetInstance().SetCameraPhotoRotation(fdp.ConsumeBool());
}

void StreamCaptureFuzzTest2(FuzzedDataProvider& fdp)
{
    auto captureId = fdp.ConsumeIntegral<int32_t>();
    auto interfaceCode = fdp.ConsumeIntegral<int32_t>();
    auto timestamp = fdp.ConsumeIntegral<uint64_t>();
    auto isDelay = fdp.ConsumeBool();
    std::string imageId(fdp.ConsumeRandomLengthString(MAX_LENGTH_STRING));
    GetInstance().SetBurstImages(captureId, imageId);
    GetInstance().CheckResetBurstKey(captureId);
    std::shared_ptr<OHOS::Camera::CameraMetadata> captureSettings;
    captureSettings = std::make_shared<OHOS::Camera::CameraMetadata>(
        fdp.ConsumeIntegralInRange(0, ITEMCOUNT), fdp.ConsumeIntegralInRange(0, DATASIZE));
    GetInstance().CheckBurstCapture(captureSettings, fdp.ConsumeIntegral<int32_t>());
    sptr<HCameraHostManager> cameraHostManager = new HCameraHostManager(nullptr);
    std::string cameraId;
    uint32_t callingTokenId = fdp.ConsumeIntegral<uint32_t>();
    sptr<HCameraDevice> camDevice = new (std::nothrow) HCameraDevice(cameraHostManager, cameraId, callingTokenId);
    camDevice->OpenDevice(true);
    GetInstance().OnCaptureReady(captureId, timestamp);
    GetInstance().Capture(captureSettings);
    GetInstance().CancelCapture();
    GetInstance().SetMode(fdp.ConsumeIntegral<int32_t>());
    GetInstance().GetMode();
    GetInstance().ConfirmCapture();
    GetInstance().EndBurstCapture(captureSettings);
    GetInstance().Release();
    GetInstance().ReleaseStream(isDelay);
    GetInstance().OnCaptureStarted(captureId);
    GetInstance().OnCaptureStarted(captureId, fdp.ConsumeIntegral<int32_t>());
    GetInstance().OnCaptureEnded(captureId, fdp.ConsumeIntegral<int32_t>());
    auto errorCode = fdp.ConsumeIntegral<int32_t>();
    GetInstance().OnCaptureError(captureId, errorCode);
    GetInstance().OnFrameShutter(captureId, timestamp);
    GetInstance().OnFrameShutterEnd(captureId, timestamp);
    CameraInfoDumper infoDumper(0);
    GetInstance().DumpStreamInfo(infoDumper);
    GetInstance().OperatePermissionCheck(interfaceCode);
    CaptureInfo captureInfoPhoto;
    GetInstance().ProcessCaptureInfoPhoto(captureInfoPhoto, captureSettings, captureId);
    GetInstance().SetRotation(captureSettings, captureId);
}

void Init()
{
    CHECK_RETURN_ELOG(!TestToken().GetAllCameraPermission(), "Get permission fail");
    g_photoSurface = Surface::CreateSurfaceAsConsumer("g_hStreamCapture");
    g_producer = g_photoSurface->GetProducer();
    sptr<SurfaceBuffer> auxPhotoBuffer = SurfaceBuffer::Create();
    if (auxPhotoBuffer != nullptr) {
        BufferRequestConfig config = {
            .width = 64,
            .height = 64,
            .strideAlignment = 0x8,
            .format = GRAPHIC_PIXEL_FMT_RGBA_8888,
            .usage = BUFFER_USAGE_CPU_READ | BUFFER_USAGE_CPU_WRITE,
            .timeout = 0,
        };
        if (auxPhotoBuffer->Alloc(config) == GSERROR_OK) {
            g_auxPhotoProxyBuffer = auxPhotoBuffer;
        }
    }
    sptr<HDI::Camera::V1_0::IStreamOperator> streamOperator;
    std::shared_ptr<OHOS::Camera::CameraMetadata> cameraAbility =
        std::make_shared<OHOS::Camera::CameraMetadata>(ITEMCOUNT, DATASIZE);
    GetInstance().LinkInput(streamOperator, cameraAbility);
    GetInstance().cameraAbility_ = cameraAbility;
}

void Test(FuzzedDataProvider& fdp)
{
    auto func = fdp.PickValueInArray({
        StreamCaptureFuzzTest1,
        StreamCaptureFuzzTest2,
        Capture,
        CancelCapture,
        SetCallback,
        Release,
        SetThumbnail,
        ConfirmCapture,
        DeferImageDeliveryFor,
        IsDeferredPhotoEnabled,
        IsDeferredVideoEnabled,
        SetBufferProducerInfo,
        SetMovingPhotoVideoCodecType,
        EnableRawDelivery,
        SetCameraPhotoRotation,
        EnableMovingPhoto,
        UnSetCallback,
        EnableOfflinePhoto,
        SetPhotoAvailableCallback,
        SetPhotoAssetAvailableCallback,
        UnSetPhotoAvailableCallback,
        UnSetPhotoAssetAvailableCallback,
        UnSetThumbnailCallback,
        CreateMediaLibrary,
        SetAutoAuxiliaryPhotosDeliveryEnabled,
        AuxPhotoStateFuzzTest,
        OnPhotoAvailableWithAuxiliary,
        OnPhotoAvailableWithAuxiliaryStub,
        OnPhotoAvailableWithAuxiliaryProxy,
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