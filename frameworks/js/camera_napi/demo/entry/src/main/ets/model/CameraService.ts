/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the 'License');
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an 'AS IS' BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import camera from '@ohos.multimedia.camera';
import fileio from '@ohos.fileio';
import image from '@ohos.multimedia.image';
import media from '@ohos.multimedia.media';
import mediaLibrary from '@ohos.multimedia.mediaLibrary';
import { BusinessError } from '@ohos.base';
import Logger from '../model/Logger';
import MediaUtils from '../model/MediaUtils';
import { Constants } from '../common/Constants';

const cameraSize = {
  width: 1280,
  height: 720
};

enum PhotoOrientation {
  ORIENTATION_0 = 0,
  ORIENTATION_1,
  ORIENTATION_2,
  ORIENTATION_3
}

const TAG: string = 'CameraService';

class CameraService {
  private mediaUtil: MediaUtils = MediaUtils.getInstance();
  private cameraManager: camera.CameraManager = undefined;
  cameras: Array<camera.CameraDevice> = undefined;
  private cameraOutputCapability: camera.CameraOutputCapability = undefined;
  private cameraInput: camera.CameraInput = undefined;
  private previewOutput: camera.PreviewOutput = undefined;
  private photoOutPut: camera.PhotoOutput = undefined;
  private captureSession: camera.CaptureSession = undefined;
  private mReceiver: image.ImageReceiver = undefined;
  private fileAsset: mediaLibrary.FileAsset = undefined;
  private fd: number = -1;
  private videoRecorder: media.AVRecorder = undefined;
  private videoOutput: camera.VideoOutput = undefined;
  private handleTakePicture: (photoUri: string) => void = undefined;
  private videoConfig: media.AVRecorderConfig = {
    audioSourceType: media.AudioSourceType.AUDIO_SOURCE_TYPE_MIC,
    videoSourceType: media.VideoSourceType.VIDEO_SOURCE_TYPE_SURFACE_YUV,
    profile: {
      audioBitrate: 48000,
      audioChannels: 2,
      audioCodec: media.CodecMimeType.AUDIO_AAC,
      audioSampleRate: 48000,
      fileFormat: media.ContainerFormatType.CFT_MPEG_4,
      videoBitrate: 512000,
      videoCodec: media.CodecMimeType.VIDEO_AVC,
      videoFrameWidth: 640,
      videoFrameHeight: 480,
      videoFrameRate: Constants.VIDEO_FRAME_30
    },
    url: '',
    rotation: 0
  };
  private videoProfiles: Array<camera.VideoProfile>;
  private videoProfilesObj: camera.VideoProfile = {
    format: 1003,
    size: {
      width: 1920,
      height: 1080
    },
    frameRateRange: {
      min: Constants.VIDEO_FRAME_30,
      max: Constants.VIDEO_FRAME_30
    }
  };
  private photoProfilesObj: camera.Profile = {
    format: 1003,
    size: {
      width: 1920,
      height: 1080
    }
  };
  private previewProfilesObj: camera.Profile = {
    format: 1003,
    size: {
      width: 1920,
      height: 1080
    }
  };
  private photoRotationMap = {
    rotation0: 0,
    rotation90: 90,
    rotation180: 180,
    rotation270: 270,
  };
  private videoOutputStatus: boolean = false;

  constructor() {
    // image capacity
    let imageCapacity = 8;
    try {
      this.mReceiver = image.createImageReceiver(cameraSize.width, cameraSize.height, image.ImageFormat.JPEG, imageCapacity);
      Logger.debug(TAG, `createImageReceiver value: ${this.mReceiver}`);
      this.mReceiver.on('imageArrival', (): void => {
        Logger.debug(TAG, 'imageArrival start');
        this.mReceiver.readNextImage((errCode: BusinessError, imageObj: image.Image): void => {
          Logger.info(TAG, 'readNextImage start');
          Logger.info(TAG, `err: ${JSON.stringify(errCode)}`);
          if (errCode || imageObj === undefined) {
            Logger.error(TAG, 'readNextImage failed');
            return;
          }
          imageObj.getComponent(image.ComponentType.JPEG, (errCode: BusinessError, component: image.Component): void => {
            Logger.debug(TAG, 'getComponent start');
            Logger.info(TAG, `err: ${JSON.stringify(errCode)}`);
            if (errCode || component === undefined) {
              Logger.info(TAG, 'getComponent failed');
              return;
            }
            let buffer: ArrayBuffer;
            if (component.byteBuffer) {
              buffer = component.byteBuffer;
            } else {
              Logger.error(TAG, 'component byteBuffer is undefined');
            }
            this.savePicture(buffer, imageObj);
          });
        });
      });
    } catch (error) {
      let err = error as BusinessError;
      Logger.error(TAG, `savePicture err: ${JSON.stringify(err)}`);
    }
  }

  /**
   * 读取图像
   */
  async savePicture(buffer: ArrayBuffer, img: image.Image): Promise<void> {
    try {
      Logger.info(TAG, 'savePicture start');
      let imgFileAsset = await this.mediaUtil.createAndGetUri(mediaLibrary.MediaType.IMAGE);
      let imgPhotoUri: string = imgFileAsset.uri;
      Logger.debug(TAG, `savePicture photoUri: ${imgPhotoUri}`);
      let imgFd = await this.mediaUtil.getFdPath(imgFileAsset);
      Logger.debug(TAG, `savePicture fd: ${imgFd}`);
      await fileio.write(imgFd, buffer);
      await imgFileAsset.close(imgFd);
      await img.release();
      Logger.info(TAG, 'savePicture End');
      if (this.handleTakePicture) {
        this.handleTakePicture(imgPhotoUri);
      }
    } catch (error) {
      let err = error as BusinessError;
      Logger.error(TAG, `savePicture err: ${JSON.stringify(err)}`);
    }
  }

  /**
   * 判断两浮点数是否相等
   */
  withinErrorMargin(left: number, right: number): boolean {
    // 底数
    let baseNumber = 2;
    // 指数
    let indexNumber = 2;
    return Math.abs(left - right) < Number.EPSILON * Math.pow(baseNumber, indexNumber);
  }

  /**
   * 初始化
   */
  async initCamera(surfaceId: string, cameraDeviceIndex: number): Promise<void> {
    try {
      // 获取传入摄像头
      Logger.debug(TAG, `initCamera cameraDeviceIndex: ${cameraDeviceIndex}`);
      await this.releaseCamera();
      // 获取相机管理器实例
      this.getCameraManagerFn();
      // 获取支持指定的相机设备对象
      this.getSupportedCamerasFn();
      const deviceType = AppStorage.get<string>('deviceType');
      let profiles = this.cameraManager.getSupportedOutputCapability(this.cameras[cameraDeviceIndex]);
      this.videoProfiles = profiles.videoProfiles;
      let defaultAspectRatio: number = AppStorage.get<number>('defaultAspectRatio');
      for (let index = profiles.previewProfiles.length - 1; index >= 0; index--) {
        const previewProfile = profiles.previewProfiles[index];
        if (this.withinErrorMargin(defaultAspectRatio, previewProfile.size.width / previewProfile.size.height)) {
          if (previewProfile.size.width <= Constants.PHOTO_MAX_WIDTH &&
            previewProfile.size.height <= Constants.PHOTO_MAX_WIDTH) {
            let previewProfileTemp = {
              format: previewProfile.format,
              size: {
                width: previewProfile.size.width,
                height: previewProfile.size.height
              }
            };
            this.previewProfilesObj = previewProfileTemp;
            Logger.debug(TAG, `previewProfilesObj: ${JSON.stringify(this.previewProfilesObj)}`);
            break;
          }
        }
      }
      for (let index = profiles.photoProfiles.length - 1; index >= 0; index--) {
        const photoProfile = profiles.photoProfiles[index];
        if (this.withinErrorMargin(defaultAspectRatio, photoProfile.size.width / photoProfile.size.height)) {
          if (photoProfile.size.width <= Constants.PHOTO_MAX_WIDTH &&
            photoProfile.size.height <= Constants.PHOTO_MAX_WIDTH) {
            let photoProfileTemp = {
              format: photoProfile.format,
              size: {
                width: photoProfile.size.width,
                height: photoProfile.size.height
              }
            };
            this.photoProfilesObj = photoProfileTemp;
            Logger.debug(TAG, `photoProfilesObj: ${JSON.stringify(this.photoProfilesObj)}`);
            break;
          }
        }
      }
      if (deviceType === Constants.DEFAULT) {
        for (let index = this.videoProfiles.length - 1; index >= 0; index--) {
          const videoProfile = this.videoProfiles[index];
          if (this.withinErrorMargin(defaultAspectRatio, videoProfile.size.width / videoProfile.size.height)) {
            if (videoProfile.size.width <= Constants.VIDEO_MAX_WIDTH &&
              videoProfile.size.height <= Constants.VIDEO_MAX_WIDTH) {
              let videoProfileTemp = {
                format: videoProfile.format,
                size: {
                  width: videoProfile.size.width,
                  height: videoProfile.size.height
                },
                frameRateRange: {
                  min: Constants.VIDEO_FRAME_30,
                  max: Constants.VIDEO_FRAME_30
                }
              };
              if ((globalThis.settingDataObj.videoFrame === 0 ? Constants.VIDEO_FRAME_15 : Constants.VIDEO_FRAME_30) ===
              videoProfile.frameRateRange.min) {
                videoProfileTemp.frameRateRange.min = videoProfile.frameRateRange.min;
                videoProfileTemp.frameRateRange.max = videoProfile.frameRateRange.max;
                Logger.debug(TAG, `videoProfilesObj: ${JSON.stringify(this.videoProfilesObj)}`);
                break;
              }
              this.videoProfilesObj = videoProfileTemp;
            }
          }
        }
      }
      // 创建previewOutput输出对象
      this.createPreviewOutputFn(this.previewProfilesObj, surfaceId);
      // 创建photoOutPut输出对象
      let mSurfaceId = await this.mReceiver.getReceivingSurfaceId();
      this.createPhotoOutputFn(this.photoProfilesObj, mSurfaceId);
      // 创建cameraInput输出对象
      this.createCameraInputFn(this.cameras[cameraDeviceIndex]);
      // 打开相机
      await this.cameraInputOpenFn();
      // 监听预览事件
      this.previewOutputCallBack();
      // 拍照监听事件
      this.photoOutPutCallBack();
      // 镜头状态回调
      this.onCameraStatusChange();
      // 手电筒状态回调
      this.onTorchStatusChange();
      // 监听CameraInput的错误事件
      this.onCameraInputChange();
      // 会话流程
      await this.sessionFlowFn();
    } catch (error) {
      let err = error as BusinessError;
      Logger.error(TAG, `initCamera fail: ${JSON.stringify(err)}`);
    }
  }

  isVideoFrameSupportedFn(videoFrame: number): boolean {
    let videoProfile: camera.VideoProfile | undefined = this.videoProfiles.find((videoProfile: camera.VideoProfile) => {
      return videoProfile.size.height === this.videoProfilesObj.size.height &&
        videoProfile.size.width === this.videoProfilesObj.size.width &&
        videoProfile.format === this.videoProfilesObj.format &&
        videoProfile.frameRateRange.min === videoFrame &&
        videoProfile.frameRateRange.max === videoFrame;
    });
    return videoProfile === undefined ? false : true;
  }

  /**
   * 曝光
   */
  isExposureModeSupportedFn(aeMode: camera.ExposureMode): void {
    // 检测曝光模式是否支持
    let isSupported = this.captureSession.isExposureModeSupported(aeMode);
    Logger.info(TAG, `isExposureModeSupported success, isSupported: ${isSupported}`);
    try {
      globalThis.promptAction.showToast({
        message: isSupported ? '支持此模式' : '不支持此模式',
        duration: 2000,
        bottom: '50%'
      });
    } catch (error) {
      let err = error as BusinessError;
      Logger.error(TAG, `showToast err: ${JSON.stringify(err)}`);
    }
    this.captureSession.setExposureMode(aeMode);
    let exposureMode = this.captureSession.getExposureMode();
    Logger.info(TAG, `getExposureMode success, exposureMode: ${exposureMode}`);
  }

  /**
   * 曝光区域
   */
  isMeteringPoint(point: camera.Point): void {
    // 获取当前曝光模式
    let exposureMode = this.captureSession.getExposureMode();
    Logger.info(TAG, `getExposureMode success, exposureMode: ${exposureMode}`);
    this.captureSession.setMeteringPoint(point);
    let exposurePoint: camera.Point = this.captureSession.getMeteringPoint();
    Logger.info(TAG, `getMeteringPoint exposurePoint: ${JSON.stringify(exposurePoint)}`);
  }

  /**
   * 曝光补偿
   */
  isExposureBiasRange(exposureBias: number): void {
    Logger.debug(TAG, `setExposureBias value ${exposureBias}`);
    // 查询曝光补偿范围
    let biasRangeArray = this.captureSession.getExposureBiasRange();
    Logger.debug(TAG, `getExposureBiasRange success, biasRangeArray: ${JSON.stringify(biasRangeArray)}`);
    // 设置曝光补偿
    this.captureSession.setExposureBias(exposureBias);
    // 查询当前曝光值
    let exposureValue = this.captureSession.getExposureValue();
    Logger.debug(TAG, `getExposureValue success, exposureValue: ${JSON.stringify(exposureValue)}`);
  }

  /**
   * 是否支持对应对焦模式
   */
  isFocusModeSupported(focusMode: camera.FocusMode): boolean {
    return this.captureSession.isFocusModeSupported(focusMode);
  }

  /**
   * 对焦模式
   */
  isFocusMode(focusMode: camera.FocusMode): void {
    // 检测对焦模式是否支持
    let isSupported = this.isFocusModeSupported(focusMode);
    Logger.info(TAG, `isFocusModeSupported isSupported: ${JSON.stringify(isSupported)}`);
    // 设置对焦模式
    this.captureSession.setFocusMode(focusMode);
    // 获取当前的对焦模式
    let nowFocusMode = this.captureSession.getFocusMode();
    Logger.info(TAG, `getFocusMode success, nowFocusMode: ${JSON.stringify(nowFocusMode)}`);
  }

  /**
   * 焦点
   */
  isFocusPoint(point: camera.Point): void {
    // 设置焦点
    this.captureSession.setFocusPoint(point);
    Logger.info(TAG, 'setFocusPoint success');
    // 获取当前的焦点
    let nowPoint = this.captureSession.getFocusPoint();
    Logger.info(TAG, `getFocusPoint success, nowPoint: ${JSON.stringify(nowPoint)}`);
  }

  /**
   * 闪关灯
   */
  hasFlashFn(flashMode: camera.FlashMode): void {
    // 检测是否有闪关灯
    let hasFlash = this.captureSession.hasFlash();
    Logger.debug(TAG, `hasFlash success, hasFlash: ${hasFlash}`);
    // 检测闪光灯模式是否支持
    let isFlashModeSupported = this.captureSession.isFlashModeSupported(flashMode);
    Logger.debug(TAG, `isFlashModeSupported success, isFlashModeSupported: ${isFlashModeSupported}`);
    // 设置闪光灯模式
    this.captureSession.setFlashMode(flashMode);
    // 获取当前设备的闪光灯模式
    let nowFlashMode = this.captureSession.getFlashMode();
    Logger.debug(TAG, `getFlashMode success, nowFlashMode: ${nowFlashMode}`);
  }

  /**
   * 手电筒灯
   */
  hasTorch(torchMode: camera.TorchMode): void {
    // 检测是否有闪关灯
    let hasFlash = this.cameraManager.isTorchSupported();
    Logger.debug(TAG, `hasFlash success, hasFlash: ${hasFlash}`);
    // 检测闪光灯模式是否支持
    let isTorchModeSupported = this.cameraManager.isTorchModeSupported(torchMode);
    Logger.debug(TAG, `isTorchModeSupported success, isTorchModeSupported: ${isTorchModeSupported}`);
    // 设置闪光灯模式
    this.cameraManager.setTorchMode(torchMode);
    // 获取当前设备的闪光灯模式
    let nowTorchMode = this.cameraManager.getTorchMode();
    Logger.debug(TAG, `getTorchMode success, nowTorchMode: ${nowTorchMode}`);
  }

  /**
   * 变焦
   */
  setZoomRatioFn(zoomRatio: number): void {
    Logger.info(TAG, `setZoomRatioFn value ${zoomRatio}`);
    // 获取支持的变焦范围
    try {
      let zoomRatioRange = this.captureSession.getZoomRatioRange();
      Logger.info(TAG, `getZoomRatioRange success: ${JSON.stringify(zoomRatioRange)}`);
    } catch (error) {
      let err = error as BusinessError;
      Logger.error(TAG, `getZoomRatioRange fail: ${JSON.stringify(err)}`);
    }

    try {
      this.captureSession.setZoomRatio(zoomRatio);
      Logger.info(TAG, 'setZoomRatioFn success');
    } catch (error) {
      let err = error as BusinessError;
      Logger.error(TAG, `setZoomRatioFn fail: ${JSON.stringify(err)}`);
    }

    try {
      let nowZoomRatio = this.captureSession.getZoomRatio();
      Logger.info(TAG, `getZoomRatio nowZoomRatio: ${JSON.stringify(nowZoomRatio)}`);
    } catch (error) {
      let err = error as BusinessError;
      Logger.error(TAG, `getZoomRatio fail: ${JSON.stringify(err)}`);
    }
  }

  /**
   * 防抖
   */
  isVideoStabilizationModeSupportedFn(videoStabilizationMode: camera.VideoStabilizationMode): void {
    // 查询是否支持指定的视频防抖模式
    let isVideoStabilizationModeSupported: boolean = this.captureSession.isVideoStabilizationModeSupported(videoStabilizationMode);
    try {
      globalThis.promptAction.showToast({
        message: isVideoStabilizationModeSupported ? '支持此模式' : '不支持此模式',
        duration: 2000,
        bottom: '50%'
      });
    } catch (error) {
      let err = error as BusinessError;
      Logger.error(TAG, `showToast err: ${JSON.stringify(err)}`);
    }
    Logger.info(TAG, `isVideoStabilizationModeSupported success: ${JSON.stringify(isVideoStabilizationModeSupported)}`);
    // 设置视频防抖
    this.captureSession.setVideoStabilizationMode(videoStabilizationMode);
    let nowVideoStabilizationMod: camera.VideoStabilizationMode = this.captureSession.getActiveVideoStabilizationMode();
    Logger.info(TAG, `getActiveVideoStabilizationMode nowVideoStabilizationMod: ${nowVideoStabilizationMod}`);
  }

  /**
   * 是否支持镜像
   */
  isMirrorSupportedFn(): void {
    let isSupported = this.photoOutPut.isMirrorSupported();
    Logger.info(TAG, `isMirrorSupported success Bol: ${JSON.stringify(isSupported)}`);
  }

  setTakePictureCallback(callback: (photoUri: string) => void): void {
    this.handleTakePicture = callback;
  }

  /**
   * 照片方向判断
   */
  onChangeRotation(): number {
    switch (globalThis.settingDataObj.photoOrientation) {
      case PhotoOrientation.ORIENTATION_1:
        return this.photoRotationMap.rotation90;
      case PhotoOrientation.ORIENTATION_2:
        return this.photoRotationMap.rotation180;
      case PhotoOrientation.ORIENTATION_3:
        return this.photoRotationMap.rotation270;
      case PhotoOrientation.ORIENTATION_0:
      default:
        return this.photoRotationMap.rotation0;
    }
  }

  /**
   * 照片地理位置逻辑 ，后续需要靠定位实现 目前传入固定值
   */
  onChangeLocation(): {
    latitude: number,
    longitude: number,
    altitude: number
  } {
    if (globalThis.settingDataObj.locationBol) {
      return { // 位置信息，经纬度
        latitude: 12.9698,
        longitude: 77.7500,
        altitude: 1000
      };
    }
    return {
      latitude: 0,
      longitude: 0,
      altitude: 0
    };
  }

  /**
   * 拍照
   */
  async takePicture(mirrorBol?: boolean): Promise<void> {
    Logger.info(TAG, 'takePicture start');
    mirrorBol = mirrorBol || false;
    this.isMirrorSupportedFn();
    let photoSettings = {
      rotation: this.onChangeRotation(),
      quality: globalThis.settingDataObj.photoQuality,
      location: this.onChangeLocation(),
      mirror: globalThis.settingDataObj.mirrorBol
    };
    Logger.debug(TAG, `takePicture photoSettings:${JSON.stringify(photoSettings)}`);
    await this.photoOutPut.capture(photoSettings);
    Logger.info(TAG, 'takePicture end');
  }

  /**
   * 配置videoOutput流
   */
  async createVideoOutput(): Promise<void> {
    Logger.info(TAG, 'createVideoOutput start');
    this.fileAsset = await this.mediaUtil.createAndGetUri(mediaLibrary.MediaType.VIDEO);
    this.fd = await this.mediaUtil.getFdPath(this.fileAsset);
    this.videoConfig.url = `fd://${this.fd}`;
    await this.videoRecorder.prepare(this.videoConfig);
    let videoId = await this.videoRecorder.getInputSurface();
    this.videoOutput = this.cameraManager.createVideoOutput(this.videoProfilesObj, videoId);
    Logger.info(TAG, 'createVideoOutput end');
  }

  /**
   * 暂停录制
   */
  async pauseVideo(): Promise<void> {
    await this.videoRecorder.pause().then((): void => {
      this.videoOutput.stop();
      this.videoOutputStatus = false;
      Logger.info(TAG, 'pauseVideo success');
    }).catch((err: BusinessError): void => {
      Logger.error(TAG, `pauseVideo failed: ${JSON.stringify(err)}`);
    });
  }

  /**
   * 恢复视频录制
   */
  async resumeVideo(): Promise<void> {
    this.videoOutput.start().then((): void => {
      this.videoOutputStatus = true;
      Logger.info(TAG, 'resumeVideo start');
      this.videoRecorder.resume().then((): void => {
        Logger.info(TAG, 'resumeVideo success');
      }).catch((err: { code?: number }): void => {
        Logger.error(TAG, `resumeVideo failed: ${JSON.stringify(err)}`);
      });
    });
  }

  /**
   * 初始化录制适配地址
   */
  async initUrl(): Promise<void> {
    this.fileAsset = await this.mediaUtil.createAndGetUri(mediaLibrary.MediaType.VIDEO);
    this.fd = await this.mediaUtil.getFdPath(this.fileAsset);
    this.videoConfig.url = `fd://${this.fd.toString()}`;
  }

  async initAVRecorder(): Promise<void> {
    if (this.videoRecorder !== undefined) {
      if (AppStorage.get<boolean>('isRecorder')) {
        await this.stopVideo();
      }
      await this.videoRecorder.release()
        .catch((err: { code?: number }): void => {
          Logger.error(TAG, `videoRecorder release failed, ${JSON.stringify(err)}`);
        });
      AppStorage.set<boolean>('isRecorder', false);
    }
    this.videoRecorder = await media.createAVRecorder();
  }

  /**
   * 开始录制
   */
  async startVideo(): Promise<void> {
    try {
      Logger.info(TAG, 'startVideo begin');
      await this.captureSession.stop();
      this.captureSession.beginConfig();
      await this.initAVRecorder();
      await this.initUrl();
      let deviceType = AppStorage.get<string>('deviceType');
      if (deviceType === Constants.DEFAULT) {
        this.videoConfig.videoSourceType = media.VideoSourceType.VIDEO_SOURCE_TYPE_SURFACE_ES;
      }
      if (deviceType === Constants.PHONE) {
        this.videoConfig.videoSourceType = media.VideoSourceType.VIDEO_SOURCE_TYPE_SURFACE_YUV;
        this.videoConfig.profile.videoCodec = media.CodecMimeType.VIDEO_MPEG4;
        this.videoConfig.rotation = this.photoRotationMap.rotation90;
      }
      if (deviceType === Constants.TABLET) {
        this.videoConfig.videoSourceType = media.VideoSourceType.VIDEO_SOURCE_TYPE_SURFACE_YUV;
      }
      this.videoConfig.profile.videoFrameWidth = this.videoProfilesObj.size.width;
      this.videoConfig.profile.videoFrameHeight = this.videoProfilesObj.size.height;
      this.videoConfig.profile.videoFrameRate = this.videoProfilesObj.frameRateRange.min;
      Logger.info(TAG, `deviceType: ${deviceType}, videoSourceType: ${JSON.stringify(this.videoConfig)}`);
      await this.videoRecorder.prepare(this.videoConfig).catch((err: { code?: number }): void => {
        Logger.error(TAG, `startVideo prepare err: ${JSON.stringify(err)}`);
      });
      let videoId = await this.videoRecorder.getInputSurface();
      Logger.debug(TAG, `startVideo videoProfilesObj: ${JSON.stringify(this.videoProfilesObj)}`);
      this.videoOutput = this.cameraManager.createVideoOutput(this.videoProfilesObj, videoId);
      this.captureSession.addOutput(this.videoOutput);
      await this.captureSession.commitConfig();
      await this.captureSession.start();
      // 监听录像事件
      this.onVideoOutputChange();
      await this.videoOutput.start();
      this.videoOutputStatus = true;
      await this.videoRecorder.start();
      AppStorage.set<boolean>('isRecorder', true);
      Logger.info(TAG, 'startVideo end');
    } catch (error) {
      let err = error as BusinessError;
      Logger.error(TAG, `startVideo err: ${JSON.stringify(err)}`);
    }
  }

  /**
   * 停止录制
   */
  async stopVideo(): Promise<mediaLibrary.FileAsset> {
    try {
      Logger.info(TAG, 'stopVideo start');
      if (this.videoRecorder) {
        await this.videoRecorder.stop();
        await this.videoRecorder.release();
      }
      if (this.videoOutputStatus) {
        await this.videoOutput.stop();
        this.videoOutputStatus = false;
      }
      AppStorage.set<boolean>('isRecorder', false);
      await this.videoOutput.release();
      this.videoOutput = undefined;
      if (this.fileAsset) {
        await this.fileAsset.close(this.fd);
        return this.fileAsset;
      }
      return undefined;
    } catch (error) {
      let err = error as BusinessError;
      Logger.error(TAG, 'stopVideo err: ' + JSON.stringify(err));
      return undefined;
    }
  }

  /**
   * 释放会话及其相关参数
   */
  async releaseCamera(): Promise<void> {
    try {
      if (this.previewOutput) {
        await this.previewOutput.stop();
        await this.previewOutput.release();
        this.previewOutput = null;
      }
      if (this.photoOutPut) {
        await this.photoOutPut.release();
        this.photoOutPut = null;
      }
      if (this.videoOutput) {
        await this.videoOutput.release();
        this.videoOutput = null;
      }
      if (this.captureSession) {
        await this.captureSession.release();
        this.captureSession = null;
      }
      if (this.cameraInput) {
        await this.cameraInput.close();
        this.cameraInput = null;
      }
      Logger.info(TAG, 'releaseCamera success');
    } catch (error) {
      let err = error as BusinessError;
      Logger.error(TAG, `releaseCamera fail: error: ${JSON.stringify(err)}`);
    }
  }

  /**
   * 释放会话
   */
  async releaseSession(): Promise<void> {
    await this.previewOutput.stop();
    await this.photoOutPut.release();
    await this.captureSession.release();
    Logger.info(TAG, 'releaseSession success');
  }

  /**
   * 获取相机管理器实例
   */
  getCameraManagerFn(): void {
    try {
      this.cameraManager = camera.getCameraManager(globalThis.abilityContext);
      Logger.info(TAG, `getCameraManager success: ${this.cameraManager}`);
    } catch (error) {
      let err = error as BusinessError;
      Logger.error(TAG, `getCameraManager failed: ${JSON.stringify(err)}`);
    }
  }

  /**
   * 获取支持指定的相机设备对象
   */
  getSupportedCamerasFn(): void {
    try {
      this.cameras = this.cameraManager.getSupportedCameras();
      Logger.info(TAG, `getSupportedCameras success: ${this.cameras}, length: ${this.cameras.length}`);
    } catch (error) {
      let err = error as BusinessError;
      Logger.error(TAG, `getSupportedCameras failed: ${JSON.stringify(err)}`);
    }
  }

  /**
   * 查询相机设备在模式下支持的输出能力
   */
  async getSupportedOutputCapabilityFn(cameraDeviceIndex: number): Promise<void> {
    this.cameraOutputCapability = this.cameraManager.getSupportedOutputCapability(this.cameras[cameraDeviceIndex]);
  }

  /**
   * 创建previewOutput输出对象
   */
  createPreviewOutputFn(photoProfilesObj: camera.Profile, surfaceId: string): void {
    try {
      this.previewOutput = this.cameraManager.createPreviewOutput(photoProfilesObj, surfaceId);
      Logger.info(TAG, `createPreviewOutput success: ${this.previewOutput}`);
    } catch (error) {
      let err = error as BusinessError;
      Logger.error(TAG, `createPreviewOutput failed: ${JSON.stringify(err)}`);
    }
  }

  /**
   * 创建photoOutPut输出对象
   */
  createPhotoOutputFn(photoProfilesObj: camera.Profile, surfaceId: string): void {
    Logger.info(TAG, `createPhotoOutputFn photoProfiles: ${JSON.stringify(photoProfilesObj)}`);
    // 获取image 拍照 的surfaceId
    this.photoOutPut = this.cameraManager.createPhotoOutput(photoProfilesObj, (surfaceId));
  }

  /**
   * 创建cameraInput输出对象
   */
  createCameraInputFn(cameraDevice: camera.CameraDevice): void {
    Logger.info(TAG, 'createCameraInputFn is called.');
    this.cameraInput = this.cameraManager.createCameraInput(cameraDevice);
  }

  /**
   * 打开相机
   */
  async cameraInputOpenFn(): Promise<void> {
    try {
      await this.cameraInput.open();
      Logger.info(TAG, 'cameraInput open success');
    } catch (error) {
      let err = error as BusinessError;
      Logger.error(TAG, `createCameraInput failed : ${JSON.stringify(err)}`);
    }
  }

  /**
   * 会话流程
   */
  async sessionFlowFn(): Promise<void> {
    try {
      // 创建CaptureSession实例
      this.captureSession = this.cameraManager.createCaptureSession();
      // 监听焦距的状态变化
      this.onFocusStateChange();
      // 监听拍照会话的错误事件
      this.onCaptureSessionErrorChange();
      // 开始配置会话
      this.captureSession.beginConfig();
      // 把CameraInput加入到会话
      this.captureSession.addInput(this.cameraInput);
      // 把previewOutput加入到会话
      this.captureSession.addOutput(this.previewOutput);
      // 把photoOutPut加入到会话
      this.captureSession.addOutput(this.photoOutPut);
      // 提交配置信息
      await this.captureSession.commitConfig();
      // 开始会话工作
      await this.captureSession.start();
      this.isFocusMode(globalThis.settingDataObj.focusMode);
      Logger.info(TAG, 'sessionFlowFn success');
    } catch (error) {
      let err = error as BusinessError;
      Logger.error(TAG, `sessionFlowFn fail : ${JSON.stringify(err)}`);
    }
  }

  /**
   * 监听拍照事件
   */
  photoOutPutCallBack(): void {
    // 监听拍照开始
    this.photoOutPut.on('captureStart', (err: BusinessError, captureId: number): void => {
      Logger.info(TAG, `photoOutPutCallBack captureStart captureId success: ${captureId}`);
    });
    // 监听拍照帧输出捕获
    // 获取时间戳转化异常
    this.photoOutPut.on('frameShutter', (err: BusinessError, frameShutterInfo: camera.FrameShutterInfo): void => {
      Logger.info(TAG, `photoOutPutCallBack frameShutter captureId: ${frameShutterInfo.captureId}, timestamp: ${frameShutterInfo.timestamp}`);
    });
    // 监听拍照结束
    this.photoOutPut.on('captureEnd', (err: BusinessError, captureEndInfo: camera.CaptureEndInfo): void => {
      Logger.info(TAG, `photoOutPutCallBack captureEnd captureId: ${captureEndInfo.captureId}, frameCount: ${captureEndInfo.frameCount}`);
    });
  }

  /**
   * 监听预览事件
   */
  previewOutputCallBack(): void {
    Logger.info(TAG, 'previewOutputCallBack is called');
    this.previewOutput.on('frameStart', (): void => {
      Logger.debug(TAG, 'Preview frame started');
    });
    this.previewOutput.on('frameEnd', (): void => {
      Logger.debug(TAG, 'Preview frame ended');
    });
    this.previewOutput.on('error', (previewOutputError: BusinessError): void => {
      Logger.info(TAG, `Preview output err: ${JSON.stringify(previewOutputError)}`);
    });
  }

  /**
   * 监听录像事件
   */
  onVideoOutputChange(): void {
    this.videoOutput.on('frameStart', (): void => {
      Logger.info(TAG, 'onVideoOutputChange frame started');
    });
    this.videoOutput.on('frameEnd', (): void => {
      Logger.info(TAG, 'onVideoOutputChange frame frameEnd');
    });
    this.videoOutput.on('error', (videoOutputError: BusinessError) => {
      Logger.error(TAG, `onVideoOutputChange fail: ${JSON.stringify(videoOutputError)}`);
    });
  }

  /**
   * 镜头状态回调
   */
  onCameraStatusChange(): void {
    this.cameraManager.on('cameraStatus', (err: BusinessError, cameraStatusInfo: camera.CameraStatusInfo): void => {
      Logger.info(TAG, `onCameraStatusChange cameraStatus success, cameraId: ${cameraStatusInfo.camera.cameraId},
      status: ${cameraStatusInfo.status}`);
    });
  }
  
  /**
   * 手电筒状态回调
   */
  onTorchStatusChange(): void {
    this.cameraManager.on('torchStatus', (err: BusinessError, torchStatusInfo: camera.TorchStatusInfo): void => {
      Logger.info(TAG, `onTorchStatusChange torchStatus success, isTorchAvailable: ${torchStatusInfo.isTorchAvailable},
      isTorchActive: ${torchStatusInfo.isTorchActive},torchLevel: ${torchStatusInfo.torchLevel}`);
    });
  }

  /**
   * 监听CameraInput的错误事件
   */
  onCameraInputChange(): void {
    this.cameraInput.on('error', this.cameras[globalThis.cameraDeviceIndex], (cameraInputError: BusinessError): void => {
      Logger.info(TAG, `onCameraInputChange cameraInput error code: ${cameraInputError.code}`);
    });
  }

  /**
   * 监听焦距的状态变化
   */
  onFocusStateChange(): void {
    this.captureSession.on('focusStateChange', (err: BusinessError, focusState: camera.FocusState): void => {
      Logger.info(TAG, `onFocusStateChange focusStateChange success : ${focusState}`);
    });
  }

  /**
   * 监听拍照会话的错误事件
   */
  onCaptureSessionErrorChange(): void {
    this.captureSession.on('error', (captureSessionError: BusinessError): void => {
      Logger.info(TAG, 'onCaptureSessionErrorChange fail: ' + JSON.stringify(captureSessionError.code));
    });
  }
}

export default new CameraService();

