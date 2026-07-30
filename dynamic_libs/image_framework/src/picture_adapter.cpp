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


#include <memory>
#include "securec.h"
#include <fstream>
#include "dfx_report.h"
#include "picture_adapter.h"
#include "camera_log.h"
#include "image_format.h"
#include "image_mime_type.h"
#include "image_type.h"
#include "ipc_skeleton.h"
#include "picture.h"
#include "pixel_map.h"
#include "surface_buffer.h"
#include <sys/stat.h>
#include <filesystem>
#include "buffer_common.h"
#include "image_packer.h"

namespace OHOS {
namespace CameraStandard {
using namespace Media;
static const std::string FACE_IS_DETECTED = "HwMnoteFaceBeautyIsDetected";

enum BufferHandleAttrKey : int32_t {
    ATTRKEY_COLORSPACE_INFO = 1,
    ATTRKEY_COLORSPACE_TYPE,
    ATTRKEY_HDR_METADATA_TYPE,
    ATTRKEY_HDR_STATIC_METADATA,
    ATTRKEY_HDR_DYNAMIC_METADATA,
    ATTRKEY_HDR_PROCESSED,
    ATTRKEY_CROP_REGION,
    ATTRKEY_EXPECT_FPS,
    ATTRKEY_DATA_ACCESS,
    ATTRKEY_GPU_DIRTY_REGION = 17,
    ATTRKEY_VENDOR_EXT_START = 2048,
    ATTRKEY_OEM_EXT_START = 4096,
    ATTRKEY_END = 8192,
};
std::unordered_map<std::string, float> exifOrientationDegree = {
    {"Top-left", 0},
    {"Top-right", 90},
    {"Bottom-right", 180},
    {"Right-top", 90},
    {"Left-bottom", 270},
};

float TransExifOrientationToDegree(const std::string& orientation)
{
    float degree = .0;
    if (exifOrientationDegree.count(orientation)) {
        degree = exifOrientationDegree[orientation];
    }
    return degree;
}

inline void RotatePixelMap(std::shared_ptr<Media::PixelMap> pixelMap, const std::string& exifOrientation)
{
    float degree = TransExifOrientationToDegree(exifOrientation);
    if (pixelMap) {
        DECORATOR_HILOG(HILOG_INFO, "RotatePicture degree is %{public}f", degree);
        pixelMap->rotate(degree);
    } else {
        DECORATOR_HILOG(HILOG_ERROR, "RotatePicture degree is %{public}f", degree);
    }
}

std::string GetAndSetExifOrientation(OHOS::Media::ImageMetadata* exifData)
{
    std::string orientation = "";
    if (exifData != nullptr) {
        exifData->GetValue("Orientation", orientation);
        std::string defalutExifOrientation = "1";
        exifData->SetValue("Orientation", defalutExifOrientation);
        DECORATOR_HILOG(HILOG_INFO, "GetExifOrientation orientation:%{public}s", orientation.c_str());
        exifData->RemoveExifThumbnail();
        MEDIA_INFO_LOG("RemoveExifThumbnail");
    } else {
        DECORATOR_HILOG(HILOG_ERROR, "GetExifOrientation exifData is nullptr");
    }
    return orientation;
}
bool PictureAdapter::RotateFaceCoordinate(std::vector<float>& floatValues, int32_t stIdx, int32_t degree)
{
    static const int32_t FACE_X1 = 0;
    static const int32_t FACE_Y1 = 1;
    static const int32_t FACE_X2 = 2;
    static const int32_t FACE_Y2 = 3;
    static const int32_t FACE_ANGLE_INDEX = 6;
    CHECK_RETURN_RET_ELOG(stIdx < 0, false, "invalid stIdx:%{public}d", stIdx);
    CHECK_RETURN_RET_ELOG(floatValues.size() <= stIdx + FACE_ANGLE_INDEX, false, "invalid size of floatValues");
    float& x1 = floatValues[stIdx + FACE_X1];
    float& y1 = floatValues[stIdx + FACE_Y1];
    float& x2 = floatValues[stIdx + FACE_X2];
    float& y2 = floatValues[stIdx + FACE_Y2];
    float& angle = floatValues[stIdx + FACE_ANGLE_INDEX];
    float ix1 = x1;
    float iy1 = y1;
    float ix2 = x2;
    float iy2 = y2;
    switch (degree) {
        case 90: {
            x1 = 1.f - iy2;
            y1 = ix1;
            x2 = 1.f - iy1;
            y2 = ix2;
            angle += 90;
            break;
        }
        case 180: {
            x1 = 1.f - ix2;
            y1 = 1.f - iy2;
            x2 = 1.f - ix1;
            y2 = 1.f - iy1;
            angle += 180;
            break;
        }
        case 270: {
            x1 = iy1;
            y1 = 1.f - ix2;
            x2 = iy2;
            y2 = 1.f - ix1;
            angle -= 90;
            break;
        }
        case 0:
            MEDIA_WARNING_LOG("0 degree, do nothing");
            break;
        default:
            MEDIA_ERR_LOG("invalid degree:%{public}d", degree);
            return false;
    }
    return true;
}

std::string PictureAdapter::RotateFaceExif(const std::string& faceInfo, int32_t faceNum, int32_t degree)
{
    CHECK_PRINT_WLOG(!degree, "degree is 0");
    CHECK_RETURN_RET_ELOG(!faceNum, "", "faceNum is 0");
    CHECK_RETURN_RET_ELOG(faceInfo.empty(), "", "faceInfo is empty");
    static const int32_t INFO_COUNT_PER_FACE = 10; // 面部信息个数per face
    static const int32_t FACE_NUM_UB = 100;
    CHECK_RETURN_RET_ELOG(faceNum < 0 || faceNum > FACE_NUM_UB, "", "invalid faceNum count:%{public}d", faceNum);
    // 解析字符串为float数值
    std::vector<float> floatValues;
    std::istringstream iss(faceInfo);
    float value;
    while (iss >> value) {
        floatValues.push_back(value);
    }

    CHECK_RETURN_RET_ELOG(static_cast<int32_t>(floatValues.size()) != faceNum * INFO_COUNT_PER_FACE, "",
        "invalid info count:%{public}zu", floatValues.size());
    for (int32_t i = 0; i < faceNum; ++i) {
        int32_t stIdx = i * INFO_COUNT_PER_FACE;
        bool isSucc = RotateFaceCoordinate(floatValues, stIdx, degree);
        CHECK_RETURN_RET_ELOG(!isSucc, "", "RotateFaceCoordinate fail");
    }

    // 转换为字符串
    std::ostringstream oss;
    for (size_t i = 0; i < floatValues.size(); i++) {
        oss << floatValues[i];
        if (i < floatValues.size() - 1) {
            oss << " ";
        }
    }
    return oss.str();
}

bool PictureAdapter::IsInteger(const std::string& str, int32_t& result)
{
    if (str.empty())
        return false;

    std::stringstream ss(str);
    ss >> result;

    // 检查是否成功读取且没有剩余字符
    return ss.eof() && !ss.fail();
}

bool PictureAdapter::RotateBeautyExif(OHOS::Media::ImageMetadata* exifData, const std::string& orientation)
{
    CHECK_RETURN_RET_ELOG(!exifData, false, "exifData is nullptr");
    static const std::string FACE_NUM = "HwMnoteFaceBeautyFaceNum";
    static const std::string FACE_INFO = "HwMnoteFaceBeautyFaceInfo";
    const std::vector<std::string> BT_KEYS = { "HwMnoteFaceBeautyVersion", FACE_IS_DETECTED, FACE_NUM, FACE_INFO,
        "HwMnoteFaceBeautyFaceBlurInfo", "HwMnoteFaceBeautyLux", "HwMnoteFaceBeautyExposureTime",
        "HwMnoteFaceBeautyISO" };
    for (auto& key : BT_KEYS) {
        std::string val = "";
        exifData->GetValue(key, val);
        MEDIA_DEBUG_LOG("key-val:%{public}s::%{public}s", key.c_str(), val.c_str());
    }

    int32_t degree = std::round(TransExifOrientationToDegree(orientation));
    CHECK_PRINT_WLOG(!degree, "degree is 0");
    MEDIA_INFO_LOG("degree is %{public}d", degree);

    std::string isDetect = "";
    exifData->GetValue(FACE_IS_DETECTED, isDetect);
    CHECK_RETURN_RET_ELOG(isDetect.empty() || isDetect == "default_exif_value" || isDetect == "0", false, "not detect");

    std::string faceNumStr = "";
    exifData->GetValue(FACE_NUM, faceNumStr);
    CHECK_RETURN_RET_ELOG(
        faceNumStr.empty() || faceNumStr == "default_exif_value" || faceNumStr == "0", false, "no face");

    int32_t faceNum = 0;
    bool isSucc = IsInteger(faceNumStr, faceNum);
    CHECK_RETURN_RET_ELOG(!isSucc, false, "invalid faceNum");

    std::string faceInfoStr = "";
    exifData->GetValue(FACE_INFO, faceInfoStr);
    CHECK_RETURN_RET_ELOG(faceInfoStr.empty() || faceInfoStr == "default_exif_value", false,
        "invalid faceInfoStr:%{public}s", faceInfoStr.c_str());

    std::string rotateFaceInfo = RotateFaceExif(faceInfoStr, faceNum, degree);
    CHECK_RETURN_RET_ELOG(rotateFaceInfo.empty(), false, "rotate fail");
    MEDIA_INFO_LOG(
        "rotate rotateFaceInfo from:\n%{public}s to\n%{public}s", faceInfoStr.c_str(), rotateFaceInfo.c_str());
    exifData->SetValue(FACE_INFO, rotateFaceInfo);
    return true;
}

PictureAdapter::PictureAdapter() : picture_(nullptr)
{
    MEDIA_INFO_LOG("PictureAdapter ctor");
}

PictureAdapter::PictureAdapter(std::shared_ptr<Media::Picture> picture) : picture_(picture)
{
    MEDIA_INFO_LOG("PictureAdapter ctor");
    if (!picture_) {
        CameraReportUtils::GetInstance().ReportCameraCreateNullptr("PictureAdapter::Create", "Media::Picture::Create");
        return;
    }
    gainPixelMap_ = picture_->GetAuxiliaryPicture(AuxiliaryPictureType::GAINMAP);
    depthPixelMap_ = picture_->GetAuxiliaryPicture(AuxiliaryPictureType::DEPTH_MAP);
}

PictureAdapter::~PictureAdapter()
{
    MEDIA_INFO_LOG("PictureAdapter dctor");
}

void PictureAdapter::Create(sptr<SurfaceBuffer> &surfaceBuffer)
{
    MEDIA_INFO_LOG("PictureAdapter ctor");
    picture_ = Media::Picture::Create(surfaceBuffer);
    CHECK_EXECUTE(!picture_,
        CameraReportUtils::GetInstance().ReportCameraCreateNullptr(
            "PictureAdapter::Create", "Media::Picture::Create"));
}

void PictureAdapter::SetAuxiliaryPicture(sptr<SurfaceBuffer> &surfaceBuffer, CameraAuxiliaryPictureType type)
{
    MEDIA_INFO_LOG("PictureAdapter::SetAuxiliaryPicture enter");
    std::shared_ptr<Media::Picture> picture = GetPicture();
    CHECK_RETURN_ELOG(!picture, "PictureAdapter::SetAuxiliaryPicture picture is nullptr");
    std::unique_ptr<Media::AuxiliaryPicture> uniptr = Media::AuxiliaryPicture::Create(
        surfaceBuffer, static_cast<Media::AuxiliaryPictureType>(type));
    std::shared_ptr<Media::AuxiliaryPicture> picturePtr = std::move(uniptr);
    picture->SetAuxiliaryPicture(picturePtr);
}

bool PictureAdapter::Marshalling(Parcel &data) const
{
    MEDIA_INFO_LOG("PictureAdapter::Marshalling enter");
    std::shared_ptr<Media::Picture> picture = GetPicture();
    CHECK_RETURN_RET_ELOG(!picture, false, "PictureAdapter::Marshalling picture is nullptr");
    bool isMarshalling = picture->Marshalling(data);
    CHECK_EXECUTE(isMarshalling == false, CameraReportUtils::GetInstance().ReportCameraFalse(
        "PictureAdapter::Marshalling", "Media::Picture::Marshalling"));
    return isMarshalling;
}

void PictureAdapter::UnmarshallingPicture(Parcel &data)
{
    MEDIA_INFO_LOG("PictureAdapter::Unmarshalling enter");
    picture_.reset(Media::Picture::Unmarshalling(data));
}

int32_t PictureAdapter::SetExifMetadata(sptr<SurfaceBuffer> &surfaceBuffer)
{
    MEDIA_DEBUG_LOG("PictureAdapter::SetExifMetadata enter");
    int32_t retCode = -1;
    std::shared_ptr<Media::Picture> picture = GetPicture();
    CHECK_RETURN_RET_ELOG(!picture, retCode, "PictureAdapter::SetExifMetadata picture is nullptr");
    retCode = static_cast<int32_t>(picture->SetExifMetadata(surfaceBuffer));
    CHECK_EXECUTE(retCode != 0, CameraReportUtils::GetInstance().ReportCameraError<int32_t>(
        "PictureAdapter::SetExifMetadata", "Media::Picture::SetExifMetadata", retCode));
    MEDIA_INFO_LOG("PictureAdapter::SetExifMetadata retCode:%{public}d", retCode);
    return retCode;
}

bool PictureAdapter::SetMaintenanceData(sptr<SurfaceBuffer> &surfaceBuffer)
{
    bool retCode = false;
    std::shared_ptr<Media::Picture> picture = GetPicture();
    CHECK_RETURN_RET_ELOG(!picture, retCode, "PictureAdapter::SetMaintenanceData picture is nullptr");
    retCode = picture->SetMaintenanceData(surfaceBuffer);
    CHECK_EXECUTE(retCode == false, CameraReportUtils::GetInstance().ReportCameraFalse(
        "PictureAdapter::SetMaintenanceData", "Media::Picture::SetMaintenanceData"));
    return retCode;
}

void PictureAdapter::RotatePicture()
{
    MEDIA_DEBUG_LOG("PictureAdapter::RotatePicture E");
    std::shared_ptr<Media::Picture> picture = GetPicture();
    CHECK_RETURN_ELOG(!picture, "PictureAdapter::RotatePicture picture is nullptr");
    std::string orientation = GetAndSetExifOrientation(
        reinterpret_cast<OHOS::Media::ImageMetadata*>(picture->GetExifMetadata().get()));
    MEDIA_INFO_LOG("PictureAdapter::RotatePicture orientation:%{public}s", orientation.c_str());
    bool isSucc =
        RotateBeautyExif(reinterpret_cast<OHOS::Media::ImageMetadata*>(picture->GetExifMetadata().get()), orientation);
    CHECK_PRINT_WLOG(!isSucc, "PictureAdapter::RotatePicture RotateBeautyExif fail");
    RotatePixelMap(picture->GetMainPixel(), orientation);
    auto gainMap = picture->GetAuxiliaryPicture(Media::AuxiliaryPictureType::GAINMAP);
    if (gainMap) {
        RotatePixelMap(gainMap->GetContentPixel(), orientation);
    }
    auto depthMap = picture->GetAuxiliaryPicture(Media::AuxiliaryPictureType::DEPTH_MAP);
    if (depthMap) {
        RotatePixelMap(depthMap->GetContentPixel(), orientation);
    }
    auto unrefocusMap = picture->GetAuxiliaryPicture(Media::AuxiliaryPictureType::UNREFOCUS_MAP);
    if (unrefocusMap) {
        RotatePixelMap(unrefocusMap->GetContentPixel(), orientation);
    }
    auto linearMap = picture->GetAuxiliaryPicture(Media::AuxiliaryPictureType::LINEAR_MAP);
    if (linearMap) {
        RotatePixelMap(linearMap->GetContentPixel(), orientation);
    }
    MEDIA_INFO_LOG("PictureAdapter::RotatePicture X");
}

bool PictureAdapter::IsFaceDetected(std::shared_ptr<Media::Picture> picture)
{
    MEDIA_DEBUG_LOG("PictureAdapter::IsFaceDetected E");
    CHECK_RETURN_RET_ELOG(!picture, false, "PictureAdapter::RotatePicture picture is nullptr");
    auto exifData = reinterpret_cast<OHOS::Media::ImageMetadata*>(picture->GetExifMetadata().get());
    CHECK_RETURN_RET_ELOG(!exifData, false, "exifData is nullptr");

    std::string isDetect = "";
    exifData->GetValue(FACE_IS_DETECTED, isDetect);
    CHECK_RETURN_RET_ELOG(isDetect.empty() || isDetect == "default_exif_value", false, "not detect");
    CHECK_RETURN_RET_ELOG(isDetect != "1", false, "isDetect false:%{public}s", isDetect.c_str());
    MEDIA_INFO_LOG("PictureAdapter::IsFaceDetected X");
    return true;
}

uint32_t PictureAdapter::SetXtStyleMetadataBlob(const uint8_t *source, const uint32_t bufferSize)
{
    MEDIA_INFO_LOG("PictureAdapter::SetXtStyleMetadataBlob E");
    uint32_t retCode = 0;
    std::shared_ptr<Media::Picture> picture = GetPicture();
    CHECK_RETURN_RET_ELOG(!picture, retCode, "PictureAdapter::SetXtStyleMetadataBlob picture is nullptr");
    auto xtStyleMetadata = std::make_shared<Media::XtStyleMetadata>();
    xtStyleMetadata->SetBlob(source, bufferSize);
    retCode = picture->SetXtStyleMetadata(xtStyleMetadata);
    CHECK_EXECUTE(retCode != 0, CameraReportUtils::GetInstance().ReportCameraError<uint32_t>(
        "PictureAdapter::SetXtStyleMetadataBlob", "Media::Picture::SetXtStyleMetadata", retCode));
    MEDIA_INFO_LOG("PictureAdapter::SetXtStyleMetadataBlob X");
    return retCode;
}

std::shared_ptr<Media::Picture> PictureAdapter::GetPicture() const
{
    return picture_;
}

bool PictureAdapter::ResizeLcdPicture()
{
    CHECK_RETURN_RET_ELOG(!picture_, false, "picture is nullptr");
    std::vector<std::shared_ptr<PixelMap>> pixelMaps;
    auto mainPixel = picture_->GetMainPixel();
    CHECK_RETURN_RET_ELOG(!mainPixel, false, "mainPixel is nullptr");
    int32_t height = mainPixel->GetHeight();
    int32_t width = mainPixel->GetWidth();
    MEDIA_INFO_LOG("process main pix");
    MEDIA_INFO_LOG(
        "before ResizePicture : height %{public}d, width %{public}d", mainPixel->GetHeight(), mainPixel->GetWidth());
    ResizeLcd(width, height);
    float widthScale = (1.0f * width) / mainPixel->GetWidth();
    float heightScale = (1.0f * height) / mainPixel->GetHeight();
    mainPixel->resize(widthScale, heightScale);
    MEDIA_INFO_LOG(
        "after ResizePicture : height %{public}d, width %{public}d", mainPixel->GetHeight(), mainPixel->GetWidth());

    std::vector<AuxiliaryPictureType> auxTypes = picture_->GetAuxiliaryPictureTypes();
    for (auto& type : auxTypes) {
        MEDIA_INFO_LOG("process aux type:%{public}d", static_cast<int32_t>(type));
        auto auxPic = picture_->GetAuxiliaryPicture(type);
        auto auxPixel = auxPic->GetContentPixel();
        CHECK_RETURN_RET_ELOG(!auxPixel, false, "auxPixel is nullptr");
        MEDIA_INFO_LOG(
            "before ResizePicture : height %{public}d, width %{public}d", auxPixel->GetHeight(), auxPixel->GetWidth());
        auxPixel->resize(widthScale, heightScale);
        MEDIA_INFO_LOG(
            "after ResizePicture : height %{public}d, width %{public}d", auxPixel->GetHeight(), auxPixel->GetWidth());
    }
    return true;
}

bool PictureAdapter::ResizeLcd(int& width, int& height)
{
    constexpr float EPSILON = 1e-6;
    constexpr int32_t LCD_LONG_SIDE_THRESHOLD = 1920;
    constexpr int32_t LCD_SHORT_SIDE_THRESHOLD = 512;
    constexpr int32_t MAXIMUM_LCD_LONG_SIDE = 4096;
    constexpr int32_t EVEN_BASE_NUMBER = 2;

    int maxLen = std::max(width, height);
    int minLen = std::min(width, height);
    if (minLen == 0) {
        MEDIA_ERR_LOG("Divisor minLen is 0");
        return false;
    }
    double ratio = static_cast<double>(maxLen) / minLen;
    if (std::abs(ratio) < EPSILON) {
        MEDIA_ERR_LOG("ratio is 0");
        return false;
    }
    int newMaxLen = maxLen;
    int newMinLen = minLen;
    if (maxLen > LCD_LONG_SIDE_THRESHOLD) {
        newMaxLen = LCD_LONG_SIDE_THRESHOLD;
        newMinLen = static_cast<int>(newMaxLen / ratio);
    }
    int lastMinLen = newMinLen;
    int lastMaxLen = newMaxLen;
    if (newMinLen < LCD_SHORT_SIDE_THRESHOLD && minLen >= LCD_SHORT_SIDE_THRESHOLD) {
        lastMinLen = LCD_SHORT_SIDE_THRESHOLD;
        lastMaxLen = static_cast<int>(lastMinLen * ratio);
        if (lastMaxLen > MAXIMUM_LCD_LONG_SIDE) {
            lastMaxLen = MAXIMUM_LCD_LONG_SIDE;
            lastMinLen = static_cast<int>(lastMaxLen / ratio);
        }
    }

    // When LCD size has changed after resize, check if width or height is odd number
    // Add one to the odd side to make sure LCD would be compressed through hardware encode
    if (std::max(width, height) != lastMaxLen) {
        lastMaxLen += lastMaxLen % EVEN_BASE_NUMBER;
        lastMinLen += lastMinLen % EVEN_BASE_NUMBER;
    }
    if (height > width) {
        width = lastMinLen;
        height = lastMaxLen;
    } else {
        width = lastMaxLen;
        height = lastMinLen;
    }
    return true;
}

uint64_t GetCurrentLocalTimeStamp()
{
    std::chrono::time_point<std::chrono::system_clock, std::chrono::milliseconds> tp =
        std::chrono::time_point_cast<std::chrono::milliseconds>(std::chrono::system_clock::now());
    auto tmp = std::chrono::duration_cast<std::chrono::milliseconds>(tp.time_since_epoch());
    return tmp.count();
}

void PictureAdapter::DumpMainPixel(const std::string& title)
{
    MEDIA_INFO_LOG("PictureAdapter::DumpMainPixel E");
    std::shared_ptr<Media::Picture> picture = GetPicture();
    CHECK_RETURN_ELOG(!picture, "PictureAdapter::DumpMainPixel picture is nullptr");
    std::shared_ptr<Media::PixelMap> mainPixel = picture->GetMainPixel();
    CHECK_RETURN_ELOG(!mainPixel, "PictureAdapter::DumpMainPixel mainPixel is nullptr");
    const std::string FILE_DIR_IN_THE_SANDBOX = "/data/service/el1/public/camera_service/";

    std::string fileName = FILE_DIR_IN_THE_SANDBOX + title + "_yuv_mainPixel_" +
        std::to_string(GetCurrentLocalTimeStamp()) + "_width_" + std::to_string(mainPixel->GetWidth()) + "_height_" +
        std::to_string(mainPixel->GetHeight()) + ".dat";
    int32_t totalSize = mainPixel->GetByteCount();
    std::ofstream outFile(fileName, std::ofstream::out | std::ios::binary);
    if (!outFile.is_open()) {
        MEDIA_ERR_LOG("PictureAdapter dump yuv write error");
        return;
    }
    MEDIA_INFO_LOG("PictureAdapter GetWidth = %{public}d GetHeight = %{public}d, size = %{public}d",
        mainPixel->GetWidth(), mainPixel->GetHeight(), totalSize);
    outFile.write(reinterpret_cast<const char*>(mainPixel->GetPixels()), totalSize);
    if (outFile.is_open()) {
        outFile.close();
    }
    MEDIA_INFO_LOG("PictureAdapter::DumpMainPixel X");
}

std::pair<std::unique_ptr<uint8_t[]>, int64_t> PictureAdapter::Encode(const std::string& encodeFormat) const
{
    // encode
    MEDIA_INFO_LOG("PictureAdapter::Encode E");
    std::shared_ptr<Picture> picture = GetPicture();
    CHECK_RETURN_RET_ELOG(!picture, {}, "PictureAdapter::Encode picture is nullptr");
    auto mainPixel = picture->GetMainPixel();
    CHECK_RETURN_RET_ELOG(!mainPixel,  {}, "PictureAdapter::Encode mainPixelMap is nullptr");
    const int32_t TWO = 2;
    auto tempBufferSize = mainPixel->GetByteCount() * TWO;
    MEDIA_INFO_LOG("PictureAdapter::Encode encode new bufferSize:%{public}d", tempBufferSize);
    std::unique_ptr<uint8_t[]> tempBuffer = std::make_unique<uint8_t[]>(tempBufferSize);
    CHECK_RETURN_RET_ELOG(tempBuffer == nullptr,  {}, "PictureAdapter::Encode encode new tempBuffer failed");
 
    int64_t packedSize = 0L;
    Media::ImagePacker imagePacker;
    Media::PackOption packOption;
    packOption.format = encodeFormat;
    packOption.needsPackProperties = true; // include exifData
    static std::unordered_map<std::string, int32_t> FORMAT_TO_QUALITY_MAP = { { "image/jpeg", 90 },
        { "image/heif", 95 }, { "image/heic", 95 } };
    CHECK_RETURN_RET_ELOG(FORMAT_TO_QUALITY_MAP.find(encodeFormat) == FORMAT_TO_QUALITY_MAP.end(), {},
        "PictureAdapter::Encode unsupported format");
    packOption.quality = FORMAT_TO_QUALITY_MAP[encodeFormat];
    packOption.desiredDynamicRange = Media::EncodeDynamicRange::AUTO;
    packOption.isEditScene = false;
    imagePacker.StartPacking(tempBuffer.get(), tempBufferSize, packOption);
 
    CHECK_RETURN_RET_ELOG(picture == nullptr,  {}, "PictureAdapter::Encode GetPicture is nullptr");
    imagePacker.AddPicture(*picture);
    imagePacker.FinalizePacking(packedSize);
    CHECK_RETURN_RET_ELOG(tempBuffer == nullptr,  {}, "PictureAdapter::Encode packet pixelMap failed");
    CHECK_RETURN_RET_ELOG(packedSize == 0, {}, "PictureAdapter::Encode packet pixelMap failed, packedSize is 0");
    MEDIA_INFO_LOG("PictureAdapter::Encode pack pixelMap success, packedSize: %{public}" PRId64, packedSize);
    std::unique_ptr<uint8_t[]> newBuffer = std::make_unique<uint8_t[]>(packedSize);
    CHECK_RETURN_RET_ELOG(newBuffer == nullptr,  {}, "PictureAdapter::Encode newBuffer failed");
    int32_t ret = memcpy_s(newBuffer.get(), packedSize, tempBuffer.get(), packedSize);
    CHECK_RETURN_RET_ELOG(ret != 0,  {}, "PictureAdapter::Encode encode memcpy_s failed");
    MEDIA_INFO_LOG("PictureAdapter::Encode X");
    return { std::move(newBuffer), packedSize };
}

void PictureAdapter::DumpEncoded(void* addr, int32_t len, std::string title)
{
    MEDIA_INFO_LOG("PictureAdapter::DumpEncoded E");
    std::string FILE_DIR_IN_THE_SANDBOX = "/data/service/el1/public/camera_service/";

    std::string fileName = FILE_DIR_IN_THE_SANDBOX + title + "_encoded_" + std::to_string(GetCurrentLocalTimeStamp()) +
        "_len_" + std::to_string(len) + ".dat";
    std::ofstream outFile(fileName, std::ofstream::out | std::ios::binary);
    if (!outFile.is_open()) {
        return;
    }
    MEDIA_INFO_LOG("PictureAdapter::DumpEncoded size = %{public}d", len);
    outFile.write(reinterpret_cast<const char*>(addr), len);
    if (outFile.is_open()) {
        outFile.close();
    }
    MEDIA_INFO_LOG("PictureAdapter::DumpEncoded X");
}

std::shared_ptr<Picture> PictureAdapter::CopyPictureSource(std::shared_ptr<Picture> picture)
{
    CHECK_RETURN_RET_ELOG(picture == nullptr, nullptr, "Picture is nullptr");
    auto pixelMap = picture->GetMainPixel();
    auto gainMap = picture->GetGainmapPixelMap();
    CHECK_RETURN_RET_ELOG(pixelMap == nullptr || gainMap == nullptr, nullptr,
        "PixelMap or gainMap is nullptr");
    MEDIA_INFO_LOG("Picture information: pixelMap format:%{public}d isHdr:%{public}d allocatorType:%{public}d, "
        "gainMap format:%{public}d isHdr:%{public}d allocatorType:%{public}d, size: %{public}d * %{public}d",
        pixelMap->GetPixelFormat(), pixelMap->IsHdr(), pixelMap->GetAllocatorType(), gainMap->GetPixelFormat(),
        gainMap->IsHdr(), gainMap->GetAllocatorType(), pixelMap->GetWidth(), pixelMap->GetHeight());
    using Media::PixelMap;
    std::shared_ptr<PixelMap> copyPixelMap = CopyPixelMapSource(pixelMap);
    CHECK_RETURN_RET_ELOG(copyPixelMap == nullptr, nullptr, "Copy pixelMap failed");

    std::shared_ptr<PixelMap> copyGainMap = CopyPixelMapSource(gainMap);
    CHECK_RETURN_RET_ELOG(copyGainMap == nullptr, nullptr, "Copy gainMap failed");

    Size copyGainMapSize = {copyGainMap->GetWidth(), copyGainMap->GetHeight()};
    auto auxiliaryPicturePtr = AuxiliaryPicture::Create(copyGainMap, AuxiliaryPictureType::GAINMAP, copyGainMapSize);
    std::shared_ptr<AuxiliaryPicture> auxiliaryPicture = std::move(auxiliaryPicturePtr);
    CHECK_RETURN_RET_ELOG(auxiliaryPicture == nullptr, nullptr, "Create auxiliaryPicture failed");

    auto copySourcePtr = Picture::Create(copyPixelMap);
    std::shared_ptr<Picture> copySource = std::move(copySourcePtr);
    copySource->SetAuxiliaryPicture(auxiliaryPicture);
    return copySource;
}

std::shared_ptr<PixelMap> PictureAdapter::CopyPixelMapSource(std::shared_ptr<PixelMap> pixelMap)
{
    CHECK_RETURN_RET_ELOG(!IsSupportCopyPixelMap(pixelMap), nullptr, "Not support copy pixelMap");
    if (IsYuvPixelMap(pixelMap)) {
        return CopyYuvPixelmap(pixelMap);
    }
    return CopyNormalPixelmap(pixelMap);
}

bool PictureAdapter::IsSupportCopyPixelMap(std::shared_ptr<PixelMap> pixelMap)
{
    CHECK_RETURN_RET_ELOG(pixelMap == nullptr, false, "PixelMap is nullptr");
    if (!IsYuvPixelMap(pixelMap)) {
        return true;
    }
    PixelFormat format = pixelMap->GetPixelFormat();
    CHECK_RETURN_RET_ELOG(!(format == PixelFormat::NV21 || format == PixelFormat::NV12), false,
        "Not support copy pixelMap, format:%{public}d", format);
    return true;
}

bool PictureAdapter::IsYuvPixelMap(std::shared_ptr<PixelMap> pixelMap)
{
    CHECK_RETURN_RET_ELOG(pixelMap == nullptr, false, "PixelMap is nullptr");
    PixelFormat format = pixelMap->GetPixelFormat();
    return format == PixelFormat::NV21 || format == PixelFormat::NV12 ||
        format == PixelFormat::YCRCB_P010 || format == PixelFormat::YCBCR_P010;
}

std::shared_ptr<PixelMap> PictureAdapter::CopyYuvPixelmap(std::shared_ptr<PixelMap> pixelMap)
{
    if (pixelMap->GetAllocatorType() == AllocatorType::DMA_ALLOC) {
        return CopyYuvPixelmapWithSurfaceBuffer(pixelMap);
    }
    return CopyNoSurfaceBufferYuvPixelmap(pixelMap);
}

std::shared_ptr<PixelMap> PictureAdapter::CopyNormalPixelmap(std::shared_ptr<PixelMap> pixelMap)
{
    Media::InitializationOptions pixelMapOpts = {
        .size = {pixelMap->GetWidth(), pixelMap->GetHeight()},
        .pixelFormat = pixelMap->GetPixelFormat(),
        .alphaType = pixelMap->GetAlphaType()
    };
    auto copyPixelMapPtr = PixelMap::Create(*pixelMap, pixelMapOpts);
    std::shared_ptr<PixelMap> copyPixelMap = std::move(copyPixelMapPtr);
    CHECK_RETURN_RET_ELOG(copyPixelMap == nullptr, nullptr, "CopyNormalPixelmap failed");
    return copyPixelMap;
}


std::shared_ptr<PixelMap> PictureAdapter::CopyYuvPixelmapWithSurfaceBuffer(
    std::shared_ptr<PixelMap> pixelMap)
{
    CHECK_RETURN_RET_ELOG(pixelMap->GetFd() == nullptr, nullptr, "Get fd failed");
    sptr<SurfaceBuffer> surfaceBuffer = reinterpret_cast<SurfaceBuffer *>(pixelMap->GetFd());
    CHECK_RETURN_RET_ELOG(surfaceBuffer == nullptr, nullptr, "Get surfaceBuffer failed");
    sptr<SurfaceBuffer> dstSurfaceBuffer = SurfaceBuffer::Create();
    CHECK_RETURN_RET_ELOG(dstSurfaceBuffer == nullptr, nullptr, "Create surfaceBuffer failed");

    BufferRequestConfig requestConfig = {
        .width = surfaceBuffer->GetWidth(),
        .height = surfaceBuffer->GetHeight(),
        .strideAlignment = 0x2,
        .format = surfaceBuffer->GetFormat(),
        .usage = surfaceBuffer->GetUsage(),
        .timeout = 0,
    };
    GSError allocRes = dstSurfaceBuffer->Alloc(requestConfig);
    CHECK_RETURN_RET_ELOG(allocRes != 0, nullptr, "Alloc surfaceBuffer failed, err:%{public}d", allocRes);
    CopySurfaceBufferInfo(surfaceBuffer, dstSurfaceBuffer);
    int32_t copyRes = memcpy_s(dstSurfaceBuffer->GetVirAddr(), dstSurfaceBuffer->GetSize(),
                               surfaceBuffer->GetVirAddr(), surfaceBuffer->GetSize());
    CHECK_RETURN_RET_ELOG(copyRes != 0, nullptr, "Copy surface buffer pixels failed, copyRes %{public}d", copyRes);

    InitializationOptions opts;
    opts.size.width = pixelMap->GetWidth();
    opts.size.height = pixelMap->GetHeight();
    opts.srcPixelFormat = pixelMap->GetPixelFormat();
    opts.pixelFormat = pixelMap->GetPixelFormat();
    opts.useDMA = true;
    std::shared_ptr<PixelMap> copyPixelMap = PixelMap::Create(opts);
    CHECK_RETURN_RET_ELOG(copyPixelMap == nullptr, nullptr, "Create pixelMap failed");

    void* nativeBuffer = dstSurfaceBuffer.GetRefPtr();
    RefBase *ref = reinterpret_cast<RefBase *>(nativeBuffer);
    ref->IncStrongRef(ref);
    copyPixelMap->SetHdrType(pixelMap->GetHdrType());
    copyPixelMap->InnerSetColorSpace(pixelMap->InnerGetGrColorSpace());
    copyPixelMap->SetPixelsAddr(dstSurfaceBuffer->GetVirAddr(), dstSurfaceBuffer.GetRefPtr(),
        dstSurfaceBuffer->GetSize(), AllocatorType::DMA_ALLOC, nullptr);
    CHECK_RETURN_RET_ELOG(!SetPixelMapYuvInfo(dstSurfaceBuffer, copyPixelMap, pixelMap->IsHdr()), nullptr,
        "SetPixelMapYuvInfo failed");
    return copyPixelMap;
}

void PictureAdapter::CopySurfaceBufferInfo(sptr<SurfaceBuffer> &source, sptr<SurfaceBuffer> &dst)
{
    CHECK_RETURN_ELOG(source == nullptr || dst == nullptr,
        "CopySurfaceBufferInfo failed, source or dst is nullptr");
    std::vector<uint8_t> hdrMetadataTypeVec;
    std::vector<uint8_t> colorSpaceInfoVec;
    std::vector<uint8_t> staticData;
    std::vector<uint8_t> dynamicData;

    if (source->GetMetadata(ATTRKEY_HDR_METADATA_TYPE, hdrMetadataTypeVec) == GSERROR_OK) {
        dst->SetMetadata(ATTRKEY_HDR_METADATA_TYPE, hdrMetadataTypeVec);
    }
    if (source->GetMetadata(ATTRKEY_COLORSPACE_INFO, colorSpaceInfoVec) == GSERROR_OK) {
        dst->SetMetadata(ATTRKEY_COLORSPACE_INFO, colorSpaceInfoVec);
    }
    if (GetSbStaticMetadata(source, staticData) && (staticData.size() > 0)) {
        SetSbStaticMetadata(dst, staticData);
    }
    if (GetSbDynamicMetadata(source, dynamicData) && (dynamicData.size()) > 0) {
        SetSbDynamicMetadata(dst, dynamicData);
    }
}


std::shared_ptr<PixelMap> PictureAdapter::CopyNoSurfaceBufferYuvPixelmap(
    std::shared_ptr<PixelMap> pixelMap)
{
    auto startPtr = pixelMap->GetPixels();
    InitializationOptions opts;
    opts.size.width = pixelMap->GetWidth();
    opts.size.height = pixelMap->GetHeight();
    opts.pixelFormat = pixelMap->GetPixelFormat();
    std::shared_ptr<PixelMap> copyPixelMap = PixelMap::Create(opts);
    CHECK_RETURN_RET_ELOG(copyPixelMap == nullptr, nullptr, "Create pixelMap failed");

    int32_t copyRes = memcpy_s(copyPixelMap->GetWritablePixels(), pixelMap->GetByteCount(),
        startPtr, pixelMap->GetByteCount());
    CHECK_RETURN_RET_ELOG(copyRes != 0, nullptr, "CopyNoSurfaceBufferYuvPixelmap failed, copyRes:%{public}d", copyRes);
    sptr<SurfaceBuffer> surfaceBuffer = nullptr;
    CHECK_RETURN_RET_ELOG(!SetPixelMapYuvInfo(surfaceBuffer, copyPixelMap, false), nullptr,
        "SetPixelMapYuvInfo failed");
    return copyPixelMap;
}

bool PictureAdapter::SetPixelMapYuvInfo(sptr<SurfaceBuffer> &surfaceBuffer,
    std::shared_ptr<PixelMap> pixelMap, bool isHdr)
{
    static constexpr uint8_t HDR_PIXEL_SIZE = 2;
    static constexpr uint8_t SDR_PIXEL_SIZE = 1;
    static constexpr int32_t PLANE_Y = 0;
    static constexpr int32_t PLANE_U = 1;
    static constexpr int32_t PLANE_V = 2;
    CHECK_RETURN_RET_ELOG(pixelMap == nullptr, false, "PixelMap is nullptr");
    uint8_t ratio = isHdr ? HDR_PIXEL_SIZE : SDR_PIXEL_SIZE;
    int32_t srcWidth = pixelMap->GetWidth();
    int32_t srcHeight = pixelMap->GetHeight();
    YUVDataInfo yuvDataInfo = { .yWidth = srcWidth,
                                .yHeight = srcHeight,
                                .uvWidth = srcWidth / 2,
                                .uvHeight = srcHeight / 2,
                                .yStride = srcWidth,
                                .uvStride = srcWidth,
                                .uvOffset = srcWidth * srcHeight};

    if (surfaceBuffer == nullptr) {
        pixelMap->SetImageYUVInfo(yuvDataInfo);
        return true;
    }
    OH_NativeBuffer_Planes *planes = nullptr;
    GSError retVal = surfaceBuffer->GetPlanesInfo(reinterpret_cast<void**>(&planes));
    if (retVal != OHOS::GSERROR_OK || planes == nullptr) {
        pixelMap->SetImageYUVInfo(yuvDataInfo);
        return true;
    }

    auto format = pixelMap->GetPixelFormat();
    if (format == PixelFormat::NV12) {
        yuvDataInfo.yStride = planes->planes[PLANE_Y].columnStride / ratio;
        yuvDataInfo.uvStride = planes->planes[PLANE_U].columnStride / ratio;
        yuvDataInfo.yOffset = planes->planes[PLANE_Y].offset / ratio;
        yuvDataInfo.uvOffset = planes->planes[PLANE_U].offset / ratio;
    } else if (format == PixelFormat::NV21) {
        yuvDataInfo.yStride = planes->planes[PLANE_Y].columnStride / ratio;
        yuvDataInfo.uvStride = planes->planes[PLANE_V].columnStride / ratio;
        yuvDataInfo.yOffset = planes->planes[PLANE_Y].offset / ratio;
        yuvDataInfo.uvOffset = planes->planes[PLANE_V].offset / ratio;
    } else {
        MEDIA_ERR_LOG("Not support SetImageYUVInfo, format:%{public}d", format);
        return false;
    }

    pixelMap->SetImageYUVInfo(yuvDataInfo);
    return true;
}

bool PictureAdapter::GetSbStaticMetadata(const sptr<SurfaceBuffer> &buffer,
    std::vector<uint8_t> &staticMetadata)
{
    return buffer->GetMetadata(ATTRKEY_HDR_STATIC_METADATA, staticMetadata) == GSERROR_OK;
}

bool PictureAdapter::GetSbDynamicMetadata(const sptr<SurfaceBuffer> &buffer,
    std::vector<uint8_t> &dynamicMetadata)
{
    return buffer->GetMetadata(ATTRKEY_HDR_DYNAMIC_METADATA, dynamicMetadata) == GSERROR_OK;
}

bool PictureAdapter::SetSbStaticMetadata(sptr<SurfaceBuffer> &buffer,
    const std::vector<uint8_t> &staticMetadata)
{
    return buffer->SetMetadata(ATTRKEY_HDR_STATIC_METADATA, staticMetadata) == GSERROR_OK;
}

bool PictureAdapter::SetSbDynamicMetadata(sptr<SurfaceBuffer> &buffer,
    const std::vector<uint8_t> &dynamicMetadata)
{
    return buffer->SetMetadata(ATTRKEY_HDR_DYNAMIC_METADATA, dynamicMetadata) == GSERROR_OK;
}

void DumpPicture(std::shared_ptr<Media::PixelMap> mainPixel)
{
    MEDIA_INFO_LOG("DumpPicture start");
    CHECK_RETURN_ELOG(!mainPixel, "DumpPicture mainPixel is nullptr");
    std::string FILE_DIR_IN_THE_SANDBOX = "/data/service/el1/public/camera_service/";
    std::filesystem::path dir(FILE_DIR_IN_THE_SANDBOX);
    std::string fileName = FILE_DIR_IN_THE_SANDBOX +
        "yuv_mainphoto_" + std::to_string(GetCurrentLocalTimeStamp()) + "_width_" +
        std::to_string(mainPixel->GetWidth()) + "_height_" + std::to_string(mainPixel->GetHeight()) + ".dat";
    int32_t totalSize = mainPixel->GetRowStride() * mainPixel->GetHeight();
    std::ofstream outFile(fileName, std::ofstream::out | std::ios::binary);
    if (!outFile.is_open()) {
        MEDIA_ERR_LOG("PictureHandlerService dump yuv write error, path=%{public}s", fileName.c_str());
        return;
    }
    MEDIA_INFO_LOG("PictureHandlerService GetWidth = %{public}d GetHeight = %{public}d",
        mainPixel->GetWidth(), mainPixel->GetHeight());
    outFile.write(reinterpret_cast<const char*>(mainPixel->GetPixels()), totalSize);
    if (outFile.is_open()) {
        outFile.close();
    }
    MEDIA_INFO_LOG("DumpPicture end");
}

void PictureAdapter::DumpMainPicture()
{
MEDIA_DEBUG_LOG("PictureAdapter::DumpMainPicture E");
std::shared_ptr<Media::Picture> picture = GetPicture();
CHECK_RETURN_ELOG(!picture, "PictureAdapter::DumpMainPicture picture is nullptr");
std::shared_ptr<Media::PixelMap> pixelMap = picture->GetMainPixel();
CHECK_RETURN_ELOG(!pixelMap, "PictureAdapter::DumpMainPicture pixelMap is nullptr");
DumpPicture(pixelMap);
}

extern "C" PictureIntf *createPictureAdapterIntf()
{
    return new PictureAdapter();
}

}  // namespace CameraStandard
}  // namespace OHOS