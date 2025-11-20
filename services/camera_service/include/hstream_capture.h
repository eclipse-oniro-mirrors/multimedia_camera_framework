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

#ifndef OHOS_CAMERA_H_STREAM_CAPTURE_H
#define OHOS_CAMERA_H_STREAM_CAPTURE_H
#include <condition_variable>
#define EXPORT_API __attribute__((visibility("default")))

#include <atomic>
#include <cstdint>
#include <iostream>
#include <refbase.h>

#include "camera_metadata_info.h"
#include "stream_capture_stub.h"
#include "hstream_common.h"
#include "v1_0/istream_operator.h"
#include "v1_2/istream_operator.h"
#include "safe_map.h"
#include "icamera_ipc_checker.h"
#include "sp_holder.h"

namespace OHOS {
namespace CameraStandard {
using OHOS::HDI::Camera::V1_0::BufferProducerSequenceable;
using namespace OHOS::HDI::Camera::V1_0;
class PhotoAssetIntf;
class PictureIntf;
class CameraServerPhotoProxy;
class HStreamOperator;
class PictureAssembler;
namespace DeferredProcessing {
class TaskManager;
}
class ConcurrentMap {
public:
    void Insert(const int32_t& key, const std::shared_ptr<PhotoAssetIntf>& value);
    std::shared_ptr<PhotoAssetIntf> Get(const int32_t& key);
    void Release();
    void Erase(const int32_t& key);
    bool ReadyToUnlock(const int32_t& key, const int32_t& step, const int32_t& mode);
    bool WaitForUnlock(const int32_t& key, const int32_t& step, const int32_t& mode,
                    const std::chrono::seconds& timeout);
    void IncreaseCaptureStep(const int32_t& key);
private:
    std::map<int32_t, std::shared_ptr<PhotoAssetIntf>> map_;
    std::map<int32_t, std::shared_ptr<std::mutex>> mutexes_;
    std::map<int32_t, int32_t> step_;
    std::map<int32_t, std::shared_ptr<std::condition_variable>> cv_;
    std::mutex map_mutex_;
};
constexpr const char* BURST_UUID_UNSET = "";
class EXPORT_API HStreamCapture : public StreamCaptureStub, public HStreamCommon, public ICameraIpcChecker {
public:
    HStreamCapture(sptr<OHOS::IBufferProducer> producer, int32_t format, int32_t width, int32_t height);
    HStreamCapture(int32_t format, int32_t width, int32_t height);
    ~HStreamCapture();

    int32_t LinkInput(wptr<OHOS::HDI::Camera::V1_0::IStreamOperator> streamOperator,
        std::shared_ptr<OHOS::Camera::CameraMetadata> cameraAbility) override;
    void SetStreamInfo(StreamInfo_V1_1 &streamInfo) override;
    int32_t SetThumbnail(bool isEnabled) override;
    int32_t EnableRawDelivery(bool enabled) override;
    int32_t EnableMovingPhoto(bool enabled) override;
    int32_t SetBufferProducerInfo(const std::string& bufName, const sptr<OHOS::IBufferProducer> &producer) override;
    int32_t DeferImageDeliveryFor(int32_t type) override;
    int32_t Capture(const std::shared_ptr<OHOS::Camera::CameraMetadata> &captureSettings) override;
    int32_t CancelCapture() override;
    int32_t ConfirmCapture() override;
    int32_t ReleaseStream(bool isDelay) override;
    int32_t Release() override;
    int32_t SetCallback(const sptr<IStreamCaptureCallback> &callback) override;
    int32_t SetPhotoAvailableCallback(const sptr<IStreamCapturePhotoCallback> &callback) override;
    int32_t SetPhotoAssetAvailableCallback(const sptr<IStreamCapturePhotoAssetCallback> &callback) override;
    int32_t SetThumbnailCallback(const sptr<IStreamCaptureThumbnailCallback> &callback) override;
    int32_t UnSetCallback() override;
    int32_t UnSetPhotoAvailableCallback() override;
    int32_t UnSetPhotoAssetAvailableCallback() override;
    int32_t UnSetThumbnailCallback() override;
    int32_t OnCaptureStarted(int32_t captureId);
    int32_t OnCaptureStarted(int32_t captureId, uint32_t exposureTime);
    int32_t OnCaptureEnded(int32_t captureId, int32_t frameCount);
    int32_t OnCaptureError(int32_t captureId, int32_t errorType);
    int32_t OnFrameShutter(int32_t captureId, uint64_t timestamp);
    int32_t OnFrameShutterEnd(int32_t captureId, uint64_t timestamp);
    int32_t OnCaptureReady(int32_t captureId, uint64_t timestamp);
    int32_t OnOfflineDeliveryFinished(int32_t captureId);
    int32_t OnPhotoAvailable(sptr<SurfaceBuffer> surfaceBuffer, const int64_t timestamp, bool isRaw);
    int32_t OnPhotoAssetAvailable(
        const int32_t captureId, const std::string &uri, int32_t cameraShotType, const std::string &burstKey);
    int32_t OnThumbnailAvailable(sptr<SurfaceBuffer> surfaceBuffer, const int64_t timestamp);
    void DumpStreamInfo(CameraInfoDumper& infoDumper) override;
    void SetRotation(const std::shared_ptr<OHOS::Camera::CameraMetadata> &captureMetadataSetting_, int32_t captureId);
    void SetMode(int32_t modeName);
    int32_t GetMode();
    int32_t IsDeferredPhotoEnabled() override;
    int32_t IsDeferredVideoEnabled() override;
    int32_t SetMovingPhotoVideoCodecType(int32_t videoCodecType) override;
    int32_t GetMovingPhotoVideoCodecType();
    int32_t OperatePermissionCheck(uint32_t interfaceCode) override;
    int32_t CallbackEnter([[maybe_unused]] uint32_t code) override;
    int32_t CallbackExit([[maybe_unused]] uint32_t code, [[maybe_unused]] int32_t result) override;
    SafeMap<int32_t, int32_t> rotationMap_ = {};
    bool IsBurstCapture(int32_t captureId) const;
    bool IsBurstCover(int32_t captureId) const;
    int32_t GetCurBurstSeq(int32_t captureId) const;
    std::string GetBurstKey(int32_t captureId) const;
    void SetBurstImages(int32_t captureId, std::string imageId);
    void CheckResetBurstKey(int32_t captureId);
    int32_t SetCameraPhotoRotation(bool isEnable) override;
    int32_t CreateMediaLibraryPhotoAssetProxy(int32_t captureId);
    int32_t UpdateMediaLibraryPhotoAssetProxy(sptr<CameraServerPhotoProxy> photoProxy);
    std::shared_ptr<PhotoAssetIntf> GetPhotoAssetInstance(int32_t captureId);
    bool GetAddPhotoProxyEnabled();
    int32_t AcquireBufferToPrepareProxy(int32_t captureId);
    int32_t EnableOfflinePhoto(bool isEnable) override;
    bool IsHasEnableOfflinePhoto();
    void SwitchToOffline();
    bool IsHasSwitchToOffline();
    void SetStreamOperator(wptr<HStreamOperator> hStreamOperator);
    int32_t CreateMediaLibrary(const sptr<CameraPhotoProxy>& photoProxy, std::string& uri, int32_t& cameraShotType,
        std::string& burstKey, int64_t timestamp) override;
    int32_t CreateMediaLibrary(sptr<CameraServerPhotoProxy>& photoProxy, std::string& uri, int32_t& cameraShotType,
        std::string& burstKey, int64_t timestamp);
    int32_t CreateMediaLibrary(std::shared_ptr<PictureIntf> picture, sptr<CameraServerPhotoProxy> &photoProxy,
        std::string &uri, int32_t &cameraShotType, std::string& burstKey, int64_t timestamp);
    int32_t RequireMemorySize(int32_t memSize);

    bool isYuvCapture_ = false;
    SpHolder<sptr<Surface>> gainmapSurface_;
    SpHolder<sptr<Surface>> deepSurface_;
    SpHolder<sptr<Surface>> exifSurface_;
    SpHolder<sptr<Surface>> debugSurface_;
    SpHolder<sptr<Surface>> rawSurface_;
    std::mutex rawSurfaceMutex_;
    SpHolder<sptr<Surface>> thumbnailSurface_;
    sptr<IBufferConsumerListener> gainmapListener_ = nullptr;
    sptr<IBufferConsumerListener> deepListener_ = nullptr;
    sptr<IBufferConsumerListener> exifListener_ = nullptr;
    sptr<IBufferConsumerListener> debugListener_ = nullptr;
    sptr<PictureAssembler> pictureAssembler_;
    std::map<int32_t, std::shared_ptr<PictureIntf>> captureIdPictureMap_;
    SpHolder<std::shared_ptr<DeferredProcessing::TaskManager>> photoTask_;
    std::shared_ptr<DeferredProcessing::TaskManager> photoSubTask_ = nullptr;
    std::shared_ptr<DeferredProcessing::TaskManager> thumbnailTask_ = nullptr;

    std::mutex g_photoImageMutex;
    std::mutex g_assembleImageMutex;
    std::map<int32_t, int32_t> captureIdAuxiliaryCountMap_;
    std::map<int32_t, int32_t> captureIdCountMap_;
    std::map<int32_t, uint32_t> captureIdHandleMap_;

    std::map<int32_t, sptr<CameraServerPhotoProxy>> photoProxyMap_;
    std::map<int32_t, sptr<SurfaceBuffer>> captureIdGainmapMap_;
    SafeMap<int32_t, sptr<SurfaceBuffer>> captureIdDepthMap_ = {};
    std::map<int32_t, sptr<SurfaceBuffer>> captureIdExifMap_;
    std::map<int32_t, sptr<SurfaceBuffer>> captureIdDebugMap_;

private:
    int32_t CheckBurstCapture(const std::shared_ptr<OHOS::Camera::CameraMetadata>& captureSettings,
                              const int32_t &preparedCaptureId);
    void SetDataSpaceForCapture(StreamInfo_V1_1 &streamInfo);
    int32_t PrepareBurst(int32_t captureId);
    void ResetBurst();
    void ResetBurstKey(int32_t captureId);
    void EndBurstCapture(const std::shared_ptr<OHOS::Camera::CameraMetadata>& captureMetadataSetting_);
    void ProcessCaptureInfoPhoto(CaptureInfo& captureInfoPhoto,
        const std::shared_ptr<OHOS::Camera::CameraMetadata>& captureSettings, int32_t captureId);
    void SetCameraPhotoProxyInfo(sptr<CameraServerPhotoProxy> cameraPhotoProxy);
    sptr<IStreamCaptureCallback> streamCaptureCallback_;
    SpHolder<sptr<IStreamCapturePhotoCallback>> photoAvaiableCallback_;
    sptr<IStreamCapturePhotoAssetCallback> photoAssetAvaiableCallback_;
    sptr<IStreamCaptureThumbnailCallback> thumbnailAvaiableCallback_;
    void FillingPictureExtendStreamInfos(StreamInfo_V1_1 &streamInfo, int32_t format);
    void FillingRawAndThumbnailStreamInfo(StreamInfo_V1_1 &streamInfo);
    void UpdateJpegBasicInfo(const std::shared_ptr<OHOS::Camera::CameraMetadata> &captureMetadataSetting,
        int32_t& rotation);
    void RegisterAuxiliaryConsumers();
    void CreateCaptureSurface();
    void CreateAuxiliarySurfaces();
    void InitCaptureThread();
    void SetRawCallbackUnLock();
    void GetLocation(const std::shared_ptr<OHOS::Camera::CameraMetadata> &captureMetadataSetting);
    std::mutex callbackLock_;
    int32_t thumbnailSwitch_;
    std::atomic<int32_t> rawDeliverySwitch_;
    int32_t movingPhotoSwitch_;
    std::condition_variable testDelay_;
    std::mutex testDelayMutex_;
    SpHolder<sptr<BufferProducerSequenceable>> thumbnailBufferQueue_;
    SpHolder<sptr<BufferProducerSequenceable>> rawBufferQueue_;
    SpHolder<sptr<BufferProducerSequenceable>> gainmapBufferQueue_;
    SpHolder<sptr<BufferProducerSequenceable>> deepBufferQueue_;
    SpHolder<sptr<BufferProducerSequenceable>> exifBufferQueue_;
    SpHolder<sptr<BufferProducerSequenceable>> debugBufferQueue_;
    int32_t modeName_;
    int32_t deferredPhotoSwitch_;
    int32_t deferredVideoSwitch_;
    bool enableCameraPhotoRotation_ = false;
    std::atomic<bool> isCaptureReady_ = true;
    std::string curBurstKey_ = BURST_UUID_UNSET;
    bool isBursting_ = false;
    std::map<int32_t, std::vector<std::string>> burstImagesMap_;
    std::map<int32_t, std::string> burstkeyMap_;
    std::map<int32_t, int32_t> burstNumMap_;
    mutable std::mutex burstLock_;
    int32_t burstNum_;
    int32_t videoCodecType_ = 0;
    std::mutex photoAssetLock_;
    ConcurrentMap photoAssetProxy_;
    bool mEnableOfflinePhoto_ = false;
    bool mSwitchToOfflinePhoto_ = false;
    int32_t mlastCaptureId = 0;
    wptr<HStreamOperator> hStreamOperator_;
    std::map<int32_t, std::unique_ptr<std::mutex>> mutexMap;
    std::mutex photoCallbackLock_;
    std::mutex thumbnailCallbackLock_;
    std::mutex streamOperatorLock_;
    SpHolder<sptr<IBufferConsumerListener>> photoListener_;
    sptr<IBufferConsumerListener> photoAssetListener_ = nullptr;
    sptr<IBufferConsumerListener> thumbnailListener_ = nullptr;
    double latitude_ = 0.0;
    double longitude_ = 0.0;
    double altitude_ = 0.0;
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_H_STREAM_CAPTURE_H
