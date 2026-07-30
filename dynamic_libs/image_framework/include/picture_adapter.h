/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef CAMERA_PICTURE_ADAPTER_INTERFACE_H
#define CAMERA_PICTURE_ADAPTER_INTERFACE_H

#include "surface_buffer.h"
#include "picture_interface.h"
#include "picture.h"
#include "pixel_map.h"
namespace OHOS::Media {
    class Picture;
}
namespace OHOS {
namespace CameraStandard {
    using Media::Picture;
    using Media::PixelMap;
class PictureAdapter : public OHOS::CameraStandard::PictureIntf {
public:
    PictureAdapter();
    PictureAdapter(std::shared_ptr<Media::Picture> picture);
    ~PictureAdapter() override;
    void Create(sptr<SurfaceBuffer> &surfaceBuffer) override;
    void SetAuxiliaryPicture(sptr<SurfaceBuffer> &surfaceBuffer,
        CameraAuxiliaryPictureType type) override;
    bool Marshalling(Parcel &data) const override;
    void UnmarshallingPicture(Parcel &data) override;
    int32_t SetExifMetadata(sptr<SurfaceBuffer> &surfaceBuffer) override;
    bool SetMaintenanceData(sptr<SurfaceBuffer> &surfaceBuffer) override;
    void RotatePicture() override;
    uint32_t SetXtStyleMetadataBlob(const uint8_t *source, const uint32_t bufferSize) override;
    bool ResizeLcdPicture() override;
    void DumpMainPixel(const std::string& title) override;
    void DumpMainPicture() override;
    std::pair<std::unique_ptr<uint8_t[]>, int64_t> Encode(const std::string& encodeFormat) const override;
    static void DumpEncoded(void* addr, int32_t len, std::string title);
    static std::shared_ptr<Picture> CopyPictureSource(std::shared_ptr<Picture> picture);
    static bool IsFaceDetected(std::shared_ptr<Media::Picture> picture);
#ifdef CAMERA_CAPTURE_YUV
    std::shared_ptr<Media::Picture> GetPicture() const override;
#else
    std::shared_ptr<Media::Picture> GetPicture() const;
#endif
private:
    // Keep the order of members in this class, the bottom member will be destroyed first
    std::shared_ptr<Media::Picture> picture_;
    std::shared_ptr<Media::AuxiliaryPicture> gainPixelMap_;
    std::shared_ptr<Media::AuxiliaryPicture> depthPixelMap_;
    static bool ResizeLcd(int32_t& width, int32_t& height);
    static std::shared_ptr<PixelMap> CopyPixelMapSource(std::shared_ptr<PixelMap> pixelMap);
    static bool IsYuvPixelMap(std::shared_ptr<PixelMap> pixelMap);
    static std::shared_ptr<PixelMap> CopyYuvPixelmap(std::shared_ptr<PixelMap> pixelMap);
    static std::shared_ptr<PixelMap> CopyNormalPixelmap(std::shared_ptr<PixelMap> pixelMap);
    static std::shared_ptr<PixelMap> CopyYuvPixelmapWithSurfaceBuffer(std::shared_ptr<PixelMap> pixelMap);
    static std::shared_ptr<PixelMap> CopyNoSurfaceBufferYuvPixelmap(std::shared_ptr<PixelMap> pixelMap);
    static bool SetPixelMapYuvInfo(sptr<SurfaceBuffer>& surfaceBuffer, std::shared_ptr<PixelMap> pixelMap, bool isHdr);
    static bool IsSupportCopyPixelMap(std::shared_ptr<PixelMap> pixelMap);
    static void CopySurfaceBufferInfo(sptr<SurfaceBuffer> &source, sptr<SurfaceBuffer> &dst);
    static bool GetSbStaticMetadata(const sptr<SurfaceBuffer> &buffer, std::vector<uint8_t> &staticMetadata);
    static bool GetSbDynamicMetadata(const sptr<SurfaceBuffer> &buffer, std::vector<uint8_t> &dynamicMetadata);
    static bool SetSbStaticMetadata(sptr<SurfaceBuffer> &buffer, const std::vector<uint8_t> &staticMetadata);
    static bool SetSbDynamicMetadata(sptr<SurfaceBuffer> &buffer, const std::vector<uint8_t> &dynamicMetadata);
    static bool RotateFaceCoordinate(std::vector<float>& floatValues, int32_t stIdx, int32_t degree);
    static std::string RotateFaceExif(const std::string& faceInfo, int32_t faceNum, int32_t degree);
    static bool IsInteger(const std::string& str, int32_t& result);
    static bool RotateBeautyExif(OHOS::Media::ImageMetadata* exifData, const std::string& orientation);
};
} // namespace CameraStandard
} // namespace OHOS

#endif // CAMERA_PICTURE_ADAPTER_INTERFACE_H