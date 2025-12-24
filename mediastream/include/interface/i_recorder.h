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
#ifndef OHOS_CAMERA_I_RECORDER_H
#define OHOS_CAMERA_I_RECORDER_H

#include <cstdint>
#include <set>
#include <string>

#include "meta/meta.h"
#include "media_core.h"

namespace OHOS {
namespace CameraStandard {

constexpr size_t DEVICE_INFO_SIZE_LIMIT = 30;
/**
 * @brief Enumerates video source types.
 *
 * @since 1.0
 * @version 1.0
 */
enum VideoSourceType : int32_t {
    /** Unsupported App Usage. */
    /** YUV video data provided through {@link Surface} */
    VIDEO_SOURCE_SURFACE_YUV = 0,
    /** Raw encoded data provided through {@link Surface} */
    VIDEO_SOURCE_SURFACE_ES,
    /** RGBA video data provided through {@link Surface} */
    VIDEO_SOURCE_SURFACE_RGBA,
    /** Invalid value */
    VIDEO_SOURCE_BUTT
};

enum AudioSourceType: int32_t {
    /** Invalid audio source */
    AUDIO_SOURCE_INVALID = -1,
    /** Default audio source */
    AUDIO_SOURCE_DEFAULT = 0,
    /** Microphone */
    AUDIO_MIC = 1,
    /** Voice recognition  */
    AUDIO_SOURCE_VOICE_RECOGNITION = 2,
    /** Voice call */
    AUDIO_SOURCE_VOICE_CALL = 4,
    /** Voice communication */
    AUDIO_SOURCE_VOICE_COMMUNICATION = 7,
    /** Voice message */
    AUDIO_SOURCE_VOICE_MESSAGE = 10,
    /** Camcorder */
    AUDIO_SOURCE_CAMCORDER = 13,
    /** Inner audio */
    AUDIO_INNER = 20,
};

/**
 * @brief Enumerates meta source types.
 *
 * @since 4.2
 * @version 4.2
 */
enum MetaSourceType : int32_t {
    /** Invalid metadata source */
    VIDEO_META_SOURCE_INVALID = -1,
    /** Video Maker info */
    VIDEO_META_MAKER_INFO,
    /** max enum */
    VIDEO_META_SOURCE_BUTT
};

enum class DepthSourceType : int32_t {
    VIDEO_DEPTH_SOURCE = 0
};

enum class PreySourceType : int32_t {
    VIDEO_PREY_SOURCE = 0
};

/**
 * @brief Enumerates output format types.
 *
 * @since 3.1
 * @version 3.1
 */
enum OutputFormatType : int32_t {
    /** Default format */
    FORMAT_DEFAULT = 0,
    /** MPEG4 format */
    FORMAT_MPEG_4 = 2,
    /** M4A format */
    FORMAT_M4A = 6,
    /** AMR format */
    FORMAT_AMR = 8,
    /** mp3 format */
    FORMAT_MP3 = 9,
    /** WAV format */
    FORMAT_WAV = 10,
    /** BUTT */
    FORMAT_BUTT,
};

/*
 * Declare the type enum value valid range for different kind of RecorderParam.
 * The "Public" means externally visible.
 * The "Private" means internally visible.
 */
enum RecorderParamSectionStart {
    PUBLIC_PARAM_SECTION_START = 0,
    PRIVATE_PARAM_SECTION_START = 0x10000,
};

enum RecorderPublicParamType : uint32_t {
    PUBLIC_PARAM_TYPE_BEGIN = PUBLIC_PARAM_SECTION_START,
    // movie begin
    MOV_PUBLIC_PARAM_BEGIN,
    MOV_ENC_FMT,
    MOV_RECTANGLE,
    MOV_BITRATE,
    MOV_FRAMERATE,
    MOV_IS_HDR,
    MOV_CAPTURERATE,
    MOV_ENABLE_TEMPORAL_SCALE,
    MOV_ENABLE_STABLE_QUALITY_MODE,
    MOV_PUBLIC_PARAM_END,
    MOV_ORIENTATION_HINT,
    // video begin
    VID_PUBLIC_PARAM_BEGIN,
    VID_ENC_FMT,
    VID_RECTANGLE,
    VID_BITRATE,
    VID_FRAMERATE,
    VID_IS_HDR,
    VID_CAPTURERATE,
    VID_ENABLE_TEMPORAL_SCALE,
    VID_ENABLE_STABLE_QUALITY_MODE,
    VID_PUBLIC_PARAM_END,
    VID_ORIENTATION_HINT,
    // audio begin
    AUD_PUBLIC_PARAM_BEGIN,
    AUD_ENC_FMT,
    AUD_SAMPLERATE,
    AUD_CHANNEL,
    AUD_BITRATE,
    AUD_PUBIC_PARAM_END,
    // meta data
    META_PARAM_BEGIN,
    META_MIME_TYPE,
    META_TIMED_KEY,
    META_SOURCE_TRACK_MIME,
    META_PARAM_END,
    // output begin,
    MAX_DURATION,
    MAX_SIZE,
    OUT_PATH,
    OUT_FD,
    NEXT_OUT_FD, // reserved.
    GEO_LOCATION,
    CUSTOM_INFO,
    GENRE_INFO,
    // depth begin
    DEP_PARAM_BEGIN,
    DEP_ENC_FMT,
    DEP_RECTANGLE,
    DEP_BITRATE,
    DEP_FRAMERATE,
    DEP_PARAM_END,
    // prey begin
    PREY_PARAM_BEGIN,
    PREY_ENC_FMT,
    PREY_RECTANGLE,
    PREY_BITRATE,
    PREY_FRAMERATE,
    PREY_PARAM_END,

    PUBLIC_PARAM_TYPE_END,
};


/**
 * @brief Enumerates video codec formats.
 *
 * @since 3.1
 * @version 3.1
 */
enum VideoCodecFormat : int32_t {
    /** Default format */
    VIDEO_DEFAULT = 0,
    /** H.264 */
    H264 = 2,
    /** MPEG4 */
    MPEG4 = 6,
    /** H.265 */
    H265 = 8,
    VIDEO_CODEC_FORMAT_BUTT,
};

/**
 * @brief Enumerates audio codec formats.
 *
 * @since 3.1
 * @version 3.1
 */
enum AudioCodecFormat : int32_t {
    /** Default format */
    AUDIO_DEFAULT = 0,
    /** Advanced Audio Coding Low Complexity (AAC-LC) */
    AAC_LC = 3,
    /** mp3 format */
    AUDIO_MPEG = 4,
    /** G711-mulaw format */
    AUDIO_G711MU = 5,
    /** AUDIO_AMR_NB format */
    AUDIO_AMR_NB = 9,
    /** AUDIO_AMR_WB format */
    AUDIO_AMR_WB = 10,
    /** Invalid value */
    AUDIO_CODEC_FORMAT_BUTT,
};

enum FileGenerationMode : int32_t {
    APP_CREATE = 0,
    AUTO_CREATE_CAMERA_SCENE = 1,
};

constexpr int32_t RECORDER_DEFAULT_AUDIO_BIT_RATE = 48000;
constexpr int32_t RECORDER_DEFAULT_AUDIO_CHANNELS = 2;
constexpr int32_t RECORDER_DEFAULT_AUDIO_SAMPLE_RATE = 48000;
constexpr int32_t RECORDER_DEFAULT_VIDEO_BIT_RATE = 48000;
constexpr int32_t RECORDER_DEFAULT_FRAME_HEIGHT = -1;
constexpr int32_t RECORDER_DEFAULT_FRAME_WIDTH = -1;
constexpr int32_t RECORDER_DEFAULT_FRAME_RATE = 30;

struct RecorderProfile {
    int32_t audioBitrate = RECORDER_DEFAULT_AUDIO_BIT_RATE;
    int32_t audioChannels = RECORDER_DEFAULT_AUDIO_CHANNELS;
    int32_t audioSampleRate = RECORDER_DEFAULT_AUDIO_SAMPLE_RATE;
    AudioCodecFormat audioCodecFormat = AudioCodecFormat::AUDIO_DEFAULT;

    int32_t videoBitrate = RECORDER_DEFAULT_VIDEO_BIT_RATE;
    int32_t videoFrameWidth = RECORDER_DEFAULT_FRAME_HEIGHT;
    int32_t videoFrameHeight = RECORDER_DEFAULT_FRAME_WIDTH;
    int32_t videoFrameRate = RECORDER_DEFAULT_FRAME_RATE;
    bool isHdr = false;
    bool enableTemporalScale = false;
    bool enableStableQualityMode = false;
    VideoCodecFormat videoCodecFormat = VideoCodecFormat::VIDEO_DEFAULT;

    OutputFormatType fileFormat = OutputFormatType::FORMAT_DEFAULT;
};

struct UserLocation {
    float latitude = 0.0f;
    float longitude = 0.0f;
};

struct MetadataInfo {
    std::string videoOrientation;
    std::string genre;
    UserLocation location;
    Media::Meta customInfo;
};

struct RecorderConfig {
    AudioSourceType audioSourceType; // source type;
    VideoSourceType videoSourceType;
    std::vector<MetaSourceType> metaSourceTypeVec;
    RecorderProfile profile;
    std::string url;
    int32_t rotation = 0; // Optional
    int32_t maxDuration = INT32_MAX; // Optional
    Media::Location location; // Optional
    MetadataInfo metadata; // Optional
    FileGenerationMode fileGenerationMode = FileGenerationMode::APP_CREATE;
    bool withVideo = false;
    bool withAudio = false;
    bool withLocation = false;
};

struct RecorderConfigInfo {
    VideoSourceType movieSourceType = VIDEO_SOURCE_BUTT;
    VideoSourceType videoSourceType = VIDEO_SOURCE_BUTT;
    AudioSourceType audioSourceType = AUDIO_SOURCE_INVALID;
    MetaSourceType metaSourceType = VIDEO_META_SOURCE_INVALID;
    DepthSourceType depthSourceType = DepthSourceType::VIDEO_DEPTH_SOURCE;
    PreySourceType preySourceType = PreySourceType::VIDEO_PREY_SOURCE;
    VideoCodecFormat movieCodecFormat = VIDEO_CODEC_FORMAT_BUTT;
    VideoCodecFormat videoCodecFormat = VIDEO_CODEC_FORMAT_BUTT;
    AudioCodecFormat audioCodecFormat = AUDIO_CODEC_FORMAT_BUTT;
    VideoCodecFormat depthCodecFormat = VIDEO_CODEC_FORMAT_BUTT;
    VideoCodecFormat preyCodecFormat = VIDEO_CODEC_FORMAT_BUTT;
    int32_t width = 0;
    int32_t height = 0;
    int32_t frameRate = 0;
    int32_t bitRate = 0;
    int32_t movieWidth = 0;
    int32_t movieHeight = 0;
    int32_t movieFrameRate = 0;
    int32_t movieBitRate = 0;
    bool isHdr = false;
    bool enableTemporalScale = false;
    bool enableStableQualityMode = false;
    double captureRate = 0.0;
    int32_t audioSampleRate = 0;
    int32_t audioChannelNum = 0;
    int32_t audioBitRate = 0;
    int32_t maxDuration = 0;
    OutputFormatType outputFormatType = FORMAT_BUTT;
    int64_t maxFileSize = 0;
    float latitude = 0.0;
    float longitude = 0.0;
    int32_t rotation = 0;
    int32_t fd = -1;
    std::string uri = "";
    int32_t movieFd = -1;
    std::string movieUri = "";
    FileGenerationMode fileGenerationMode = APP_CREATE;
    std::string metaSrcTrackMime;
    Media::Meta customInfo;
    std::string genre;
    std::string metaMimeType;
    std::string metaTimedKey;
    int32_t depthWidth{0};
    int32_t depthHeight{0};
    int32_t depthBitRate{0};
    int32_t preyWidth{0};
    int32_t preyHeight{0};
    int32_t preyBitRate{0};
    bool withMovie = false;
    bool withVideo = false;
    bool withAudio = false;
    bool withDepth = false;
    bool withPrey = false;
    bool withLocation = false;
};

/*
 * Recorder parameter base structure, inherite to it to extend the new parameter.
 */
struct RecorderParam {
    explicit RecorderParam(uint32_t t) : type(t) {}
    RecorderParam() = delete;
    virtual ~RecorderParam() = default;
    bool IsVideoParam() const
    {
        return (type > VID_PUBLIC_PARAM_BEGIN) && (type < VID_PUBLIC_PARAM_END);
    }

    bool IsMetaParam() const
    {
        return (type >= META_PARAM_BEGIN) && (type < META_PARAM_END);
    }

    bool IsAudioParam() const
    {
        return (type > AUD_PUBLIC_PARAM_BEGIN) && (type < AUD_PUBIC_PARAM_END);
    }

    uint32_t type;
};

struct VidEnc : public RecorderParam {
    explicit VidEnc(VideoCodecFormat fmt) : RecorderParam(RecorderPublicParamType::VID_ENC_FMT), encFmt(fmt) {}
    VideoCodecFormat encFmt;
};

struct VidRectangle : public RecorderParam {
    VidRectangle(int32_t w, int32_t h) : RecorderParam(RecorderPublicParamType::VID_RECTANGLE), width(w), height(h) {}
    int32_t width;
    int32_t height;
};

struct VidBitRate : public RecorderParam {
    explicit VidBitRate(int32_t br) : RecorderParam(RecorderPublicParamType::VID_BITRATE), bitRate(br) {}
    int32_t bitRate;
};

struct VidFrameRate : public RecorderParam {
    explicit VidFrameRate(int32_t r) : RecorderParam(RecorderPublicParamType::VID_FRAMERATE), frameRate(r) {}
    int32_t frameRate;
};

struct VidIsHdr : public RecorderParam {
    explicit VidIsHdr(bool r) : RecorderParam(RecorderPublicParamType::VID_IS_HDR), isHdr(r) {}
    bool isHdr;
};

struct VidEnableTemporalScale : public RecorderParam {
    explicit VidEnableTemporalScale(bool r)
        : RecorderParam(RecorderPublicParamType::VID_ENABLE_TEMPORAL_SCALE), enableTemporalScale(r) {}
    bool enableTemporalScale;
};

struct VidEnableStableQualityMode : public RecorderParam {
    explicit VidEnableStableQualityMode(bool r)
        : RecorderParam(RecorderPublicParamType::VID_ENABLE_STABLE_QUALITY_MODE), enableStableQualityMode(r) {}
    bool enableStableQualityMode;
};

struct MovEnc : public RecorderParam {
    explicit MovEnc(VideoCodecFormat fmt) : RecorderParam(RecorderPublicParamType::MOV_ENC_FMT), encFmt(fmt) {}
    VideoCodecFormat encFmt;
};

struct MovRectangle : public RecorderParam {
    MovRectangle(int32_t w, int32_t h) : RecorderParam(RecorderPublicParamType::MOV_RECTANGLE), width(w), height(h) {}
    int32_t width;
    int32_t height;
};

struct MovBitRate : public RecorderParam {
    explicit MovBitRate(int32_t br) : RecorderParam(RecorderPublicParamType::MOV_BITRATE), bitRate(br) {}
    int32_t bitRate;
};

struct MovFrameRate : public RecorderParam {
    explicit MovFrameRate(int32_t r) : RecorderParam(RecorderPublicParamType::MOV_FRAMERATE), frameRate(r) {}
    int32_t frameRate;
};

struct MovIsHdr : public RecorderParam {
    explicit MovIsHdr(bool r) : RecorderParam(RecorderPublicParamType::MOV_IS_HDR), isHdr(r) {}
    bool isHdr;
};

struct MovEnableTemporalScale : public RecorderParam {
    explicit MovEnableTemporalScale(bool r)
        : RecorderParam(RecorderPublicParamType::MOV_ENABLE_TEMPORAL_SCALE), enableTemporalScale(r) {}
    bool enableTemporalScale;
};

struct MovEnableStableQualityMode : public RecorderParam {
    explicit MovEnableStableQualityMode(bool r)
        : RecorderParam(RecorderPublicParamType::MOV_ENABLE_STABLE_QUALITY_MODE), enableStableQualityMode(r) {}
    bool enableStableQualityMode;
};

struct CaptureRate : public RecorderParam {
    explicit CaptureRate(double cr) : RecorderParam(RecorderPublicParamType::VID_CAPTURERATE), capRate(cr) {}
    double capRate;
};

struct AudEnc : public RecorderParam {
    explicit AudEnc(AudioCodecFormat fmt) : RecorderParam(RecorderPublicParamType::AUD_ENC_FMT), encFmt(fmt) {}
    AudioCodecFormat encFmt;
};

struct AudSampleRate : public RecorderParam {
    explicit AudSampleRate(int32_t sr) : RecorderParam(RecorderPublicParamType::AUD_SAMPLERATE), sampleRate(sr) {}
    int32_t sampleRate;
};

struct AudChannel : public RecorderParam {
    explicit AudChannel(int32_t num) : RecorderParam(RecorderPublicParamType::AUD_CHANNEL), channel(num) {}
    int32_t channel;
};

struct AudBitRate : public RecorderParam {
    explicit AudBitRate(int32_t br) : RecorderParam(RecorderPublicParamType::AUD_BITRATE), bitRate(br) {}
    int32_t bitRate;
};

struct MaxDuration : public RecorderParam {
    explicit MaxDuration(int32_t maxDur) : RecorderParam(RecorderPublicParamType::MAX_DURATION), duration(maxDur) {}
    int32_t duration;
};

struct MaxFileSize : public RecorderParam {
    explicit MaxFileSize(int64_t maxSize) : RecorderParam(RecorderPublicParamType::MAX_SIZE), size(maxSize) {}
    int64_t size;
};

struct GeoLocation : public RecorderParam {
    explicit GeoLocation(float lat, float lng)
        : RecorderParam(RecorderPublicParamType::GEO_LOCATION), latitude(lat), longitude(lng) {}
    float latitude;
    float longitude;
};

struct RotationAngle : public RecorderParam {
    explicit RotationAngle(int32_t angle)
        : RecorderParam(RecorderPublicParamType::VID_ORIENTATION_HINT), rotation(angle) {}
    int32_t rotation;
};

struct OutFilePath : public RecorderParam {
    explicit OutFilePath(const std::string &filePath)
        : RecorderParam(RecorderPublicParamType::OUT_PATH), path(filePath) {}
    std::string path;
};

struct OutFd : public RecorderParam {
    explicit OutFd(int32_t outFd) : RecorderParam(RecorderPublicParamType::OUT_FD), fd(outFd) {}
    int32_t fd;
};

struct NextOutFd : public RecorderParam {
    explicit NextOutFd(int32_t nextOutFd) : RecorderParam(RecorderPublicParamType::NEXT_OUT_FD), fd(nextOutFd) {}
    int32_t fd;
};

struct CustomInfo : public RecorderParam {
    explicit CustomInfo(Media::Meta CustomInfo) : RecorderParam(RecorderPublicParamType::CUSTOM_INFO),
        userCustomInfo(CustomInfo) {}
    Media::Meta userCustomInfo;
};

struct GenreInfo : public RecorderParam {
    explicit GenreInfo(std::string genreInfo) : RecorderParam(RecorderPublicParamType::GENRE_INFO),
        genre(genreInfo) {}
    std::string genre;
};

struct MetaMimeType : public RecorderParam {
    explicit MetaMimeType(const std::string_view &type) : RecorderParam(RecorderPublicParamType::META_MIME_TYPE),
        mimeType(type) {}
    std::string mimeType;
};

struct MetaTimedKey : public RecorderParam {
    explicit MetaTimedKey(const std::string_view &key) : RecorderParam(RecorderPublicParamType::META_TIMED_KEY),
        timedKey(key) {}
    std::string timedKey;
};

struct MetaSourceTrackMime : public RecorderParam {
    explicit MetaSourceTrackMime(std::string_view type)
        : RecorderParam(RecorderPublicParamType::META_SOURCE_TRACK_MIME), sourceMime(type) {}
    std::string sourceMime;
};

struct DepEnc : public RecorderParam {
    explicit DepEnc(VideoCodecFormat fmt) : RecorderParam(RecorderPublicParamType::DEP_ENC_FMT), encFmt(fmt) {}
    VideoCodecFormat encFmt;
};

struct DepRectangle : public RecorderParam {
    DepRectangle(int32_t w, int32_t h) : RecorderParam(RecorderPublicParamType::DEP_RECTANGLE), width(w), height(h) {}
    int32_t width;
    int32_t height;
};

struct DepBitRate : public RecorderParam {
    explicit DepBitRate(int32_t br) : RecorderParam(RecorderPublicParamType::DEP_BITRATE), bitRate(br) {}
    int32_t bitRate;
};

struct DepFrameRate : public RecorderParam {
    explicit DepFrameRate(int32_t r) : RecorderParam(RecorderPublicParamType::DEP_FRAMERATE), frameRate(r) {}
    int32_t frameRate;
};

struct PreyEnc : public RecorderParam {
    explicit PreyEnc(VideoCodecFormat fmt) : RecorderParam(RecorderPublicParamType::PREY_ENC_FMT), encFmt(fmt) {}
    VideoCodecFormat encFmt;
};

struct PreyRectangle : public RecorderParam {
    PreyRectangle(int32_t w, int32_t h) : RecorderParam(RecorderPublicParamType::PREY_RECTANGLE), width(w), height(h) {}
    int32_t width;
    int32_t height;
};

struct PreyBitRate : public RecorderParam {
    explicit PreyBitRate(int32_t br) : RecorderParam(RecorderPublicParamType::PREY_BITRATE), bitRate(br) {}
    int32_t bitRate;
};

struct PreyFrameRate : public RecorderParam {
    explicit PreyFrameRate(int32_t r) : RecorderParam(RecorderPublicParamType::PREY_FRAMERATE), frameRate(r) {}
    int32_t frameRate;
};

struct AudioCapturerInfo {
    int32_t sourceType;
    int32_t capturerFlags;

    AudioCapturerInfo() = default;
    ~AudioCapturerInfo()= default;
    bool Marshalling(Parcel &parcel) const
    {
        return parcel.WriteInt32(sourceType)
            && parcel.WriteInt32(capturerFlags);
    }
    void Unmarshalling(Parcel &parcel)
    {
        sourceType = parcel.ReadInt32();
        capturerFlags = parcel.ReadInt32();
    }
};


struct DeviceStreamInfo {
    int32_t encoding;
    int32_t format;
    std::set<int32_t> samplingRate;
    std::set<int32_t> channels;

    DeviceStreamInfo() = default;

    bool Marshalling(Parcel &parcel) const
    {
        if (!parcel.WriteInt32(encoding)) {
            return false;
        }
        if (!parcel.WriteInt32(format)) {
            return false;
        }
        size_t size = samplingRate.size();
        if (!parcel.WriteUint64(size)) {
            return false;
        }
        for (const auto &i : samplingRate) {
            if (!parcel.WriteInt32(i)) {
                return false;
            }
        }
        size = channels.size();
        if (!parcel.WriteUint64(size)) {
            return false;
        }
        for (const auto &i : channels) {
            if (!parcel.WriteInt32(i)) {
                return false;
            }
        }
        return true;
    }
    void Unmarshalling(Parcel &parcel)
    {
        encoding = parcel.ReadInt32();
        format = parcel.ReadInt32();
        size_t size = parcel.ReadUint64();
        // it may change in the future, Restricted by security requirements
        if (size > DEVICE_INFO_SIZE_LIMIT) {
            return;
        }
        for (size_t i = 0; i < size; i++) {
            samplingRate.insert(parcel.ReadInt32());
        }
        size = parcel.ReadUint64();
        if (size > DEVICE_INFO_SIZE_LIMIT) {
            return;
        }
        for (size_t i = 0; i < size; i++) {
            channels.insert(parcel.ReadInt32());
        }
    }
};

struct DeviceInfo {
    int32_t deviceType;
    int32_t deviceRole;
    int32_t deviceId;
    int32_t channelMasks;
    int32_t channelIndexMasks;
    std::string deviceName;
    std::string macAddress;
    DeviceStreamInfo audioStreamInfo;
    std::string networkId;
    std::string displayName;
    int32_t interruptGroupId;
    int32_t volumeGroupId;
    bool isLowLatencyDevice;

    DeviceInfo() = default;
    ~DeviceInfo() = default;
    bool Marshalling(Parcel &parcel) const
    {
        return parcel.WriteInt32(deviceType)
            && parcel.WriteInt32(deviceRole)
            && parcel.WriteInt32(deviceId)
            && parcel.WriteInt32(channelMasks)
            && parcel.WriteInt32(channelIndexMasks)
            && parcel.WriteString(deviceName)
            && parcel.WriteString(macAddress)
            && audioStreamInfo.Marshalling(parcel)
            && parcel.WriteString(networkId)
            && parcel.WriteString(displayName)
            && parcel.WriteInt32(interruptGroupId)
            && parcel.WriteInt32(volumeGroupId)
            && parcel.WriteBool(isLowLatencyDevice);
    }
    void Unmarshalling(Parcel &parcel)
    {
        deviceType = parcel.ReadInt32();
        deviceRole = parcel.ReadInt32();
        deviceId = parcel.ReadInt32();
        channelMasks = parcel.ReadInt32();
        channelIndexMasks = parcel.ReadInt32();
        deviceName = parcel.ReadString();
        macAddress = parcel.ReadString();
        audioStreamInfo.Unmarshalling(parcel);
        networkId = parcel.ReadString();
        displayName = parcel.ReadString();
        interruptGroupId = parcel.ReadInt32();
        volumeGroupId = parcel.ReadInt32();
        isLowLatencyDevice = parcel.ReadBool();
    }
};

/**
 * same as AudioCapturerChangeInfo in audio_info.h
*/
class AudioRecorderChangeInfo {
public:
    int32_t createrUID;
    int32_t clientUID;
    int32_t sessionId;
    int32_t clientPid;
    AudioCapturerInfo capturerInfo;
    int32_t capturerState;
    DeviceInfo inputDeviceInfo;
    bool muted;

    AudioRecorderChangeInfo(const AudioRecorderChangeInfo &audioRecorderChangeInfo)
    {
        *this = audioRecorderChangeInfo;
    }
    AudioRecorderChangeInfo() = default;
    ~AudioRecorderChangeInfo() = default;
    bool Marshalling(Parcel &parcel) const
    {
        return parcel.WriteInt32(createrUID)
            && parcel.WriteInt32(clientUID)
            && parcel.WriteInt32(sessionId)
            && parcel.WriteInt32(clientPid)
            && capturerInfo.Marshalling(parcel)
            && parcel.WriteInt32(capturerState)
            && inputDeviceInfo.Marshalling(parcel)
            && parcel.WriteBool(muted);
    }
    void Unmarshalling(Parcel &parcel)
    {
        createrUID = parcel.ReadInt32();
        clientUID = parcel.ReadInt32();
        sessionId = parcel.ReadInt32();
        clientPid = parcel.ReadInt32();
        capturerInfo.Unmarshalling(parcel);
        capturerState = parcel.ReadInt32();
        inputDeviceInfo.Unmarshalling(parcel);
        muted = parcel.ReadBool();
    }
};

/**
 * @brief Enumerates recording error types.
 *
 * @since 1.0
 * @version 1.0
 */
enum RecorderErrorType : int32_t {
    /* internal errors, error code passed by the errorCode, and definition see "MediaServiceErrCode" */
    RECORDER_ERROR_INTERNAL,

     /** extend error start,The extension error code agreed upon by the plug-in and
         the application will be transparently transmitted by the service. */
    RECORDER_ERROR_EXTEND_START = 0X10000,
};

enum class StateId {
    INIT,
    RECORDING_SETTING,
    READY,
    PAUSE,
    RECORDING,
    ERROR,
    BUTT,
};

/**
 * @brief Provides listeners for recording errors and information events.
 *
 * @since 1.0
 * @version 1.0
 */
class RecorderCallback {
public:
    virtual ~RecorderCallback() = default;

    /**
     * @brief Called when an error occurs during recording. This callback is used to report recording errors.
     *
     * @param errorType Indicates the error type. For details, see {@link RecorderErrorType}.
     * @param errorCode Indicates the error code.
     * @since 1.0
     * @version 1.0
     */
    virtual void OnError(RecorderErrorType errorType, int32_t errorCode) = 0;

    /**
     * @brief Called when an information event occurs during recording. This callback is used to report recording
     * information.
     *
     * @param type Indicates the information type. For details, see {@link RecorderInfoType}.
     * @param extra Indicates other information, for example, the start time position of a recording file.
     * @since 1.0
     * @version 1.0
     */
    virtual void OnInfo(int32_t type, int32_t extra) = 0;
    /**
     * @brief Called when the recording configuration changes. This callback is used to report all information
     * after recording configuration changes
     *
     * @param audioCaptureChangeInfo audio Capture Change information.
     * @since 1.0
     * @version 1.0
     */
    virtual void OnAudioCaptureChange(const AudioRecorderChangeInfo &audioRecorderChangeInfo)
    {
        (void)audioRecorderChangeInfo;
    }
    
    virtual void OnPhotoAssetAvailable(const std::string &uri)
    {
        (void)uri;
    }
};

}
}
#endif
