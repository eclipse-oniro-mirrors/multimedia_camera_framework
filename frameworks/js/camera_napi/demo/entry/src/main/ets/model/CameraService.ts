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
// @ts-nocheck
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
  private captureMode: number = 0;
  private mediaUtil: MediaUtils = MediaUtils.getInstance();
  private cameraManager: camera.CameraManager | undefined = undefined;
  private cameras: Array<camera.CameraDevice> | undefined = undefined;
  private sceneModes: Array<camera.SceneMode> | undefined = undefined;
  private cameraOutputCapability: camera.CameraOutputCapability | undefined = undefined;
  private cameraInput: camera.CameraInput | undefined = undefined;
  private previewOutput: camera.PreviewOutput | undefined = undefined;
  private photoOutPut: camera.PhotoOutput | undefined = undefined;
  private captureSession: camera.CaptureSession | undefined = undefined;
  private portraitSession: camera.PortraitPhotoSession | undefined = undefined;
  private mReceiver: image.ImageReceiver | undefined = undefined;
  private fileAsset: mediaLibrary.FileAsset | undefined = undefined;
  private fd: number = -1;
  private videoRecorder: media.AVRecorder | undefined = undefined;
  private videoOutput: camera.VideoOutput | undefined = undefined;
  private handleTakePicture: (photoUri: string) => void | undefined = undefined;
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
  private videoProfileObj: camera.VideoProfile = {
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
  private defaultProfile: camera.Profile = {
    format: 1003,
    size: {
      width: 1920,
      height: 1080
    }
  };
  private photoProfileObj: camera.Profile = {
    format: 1003,
    size: {
      width: 1920,
      height: 1080
    }
  };
  private previewProfileObj: camera.Profile = {
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
  private colorEffect: camera.ColorEffectType | undefined = undefined;
  private isPortraitMode: boolean = false;

  constructor() {
    // image capacity
    let imageCapacity = 8;
    try {
      this.mReceiver = image.createImageReceiver(cameraSize.width, cameraSize.height, image.ImageFormat.JPEG, imageCapacity);
      Logger.debug(TAG, `createImageReceiver value: ${this.mReceiver}`);
      // debug版本可能监听进不来
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

  setIsPortraitMode(isPortraitMode): void {
    this.isPortraitMode = isPortraitMode;
  }

  getIsPortraitMode(): boolean {
    return this.isPortraitMode;
  }

  initProfile(cameraDeviceIndex: number): void {
    const deviceType = AppStorage.get<string>('deviceType');
    let profiles = this.cameraManager.getSupportedOutputCapability(this.cameras[cameraDeviceIndex]);
    this.videoProfiles = profiles.videoProfiles;
    let defaultAspectRatio: number = AppStorage.get<number>('defaultAspectRatio');
    if (!this.isPortraitMode) {
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
            this.previewProfileObj = previewProfileTemp;
            Logger.debug(TAG, `previewProfileObj: ${JSON.stringify(this.previewProfileObj)}`);
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
            this.photoProfileObj = photoProfileTemp;
            Logger.debug(TAG, `photoProfileObj: ${JSON.stringify(this.photoProfileObj)}`);
            break;
          }
        }
      }
    } else {
      // 不是所有的profile都支持PortraitMode
      this.photoProfileObj = this.previewProfileObj = this.defaultProfile;
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
              Logger.debug(TAG, `videoProfileObj: ${JSON.stringify(this.videoProfileObj)}`);
              break;
            }
            this.videoProfileObj = videoProfileTemp;
          }
        }
      }
    }
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
      if (this.isPortraitMode) {
        this.getModeManagerFn();
      }
      // 获取支持指定的相机设备对象
      this.getSupportedCamerasFn();
      if (this.isPortraitMode) {
        this.getSupportedModeFn(cameraDeviceIndex);
      }
      this.initProfile(cameraDeviceIndex);
      // 创建previewOutput输出对象
      this.createPreviewOutputFn(this.previewProfileObj, surfaceId);
      // 创建photoOutPut输出对象
      let mSurfaceId = await this.mReceiver.getReceivingSurfaceId();
      this.createPhotoOutputFn(this.photoProfileObj, mSurfaceId);
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
      // 监听CameraInput的错误事件
      this.onCameraInputChange();
      // 会话流程
      if (this.isPortraitMode) {
        await this.portraitSessionFlowFn(cameraDeviceIndex);
      } else {
        await this.sessionFlowFn();
      }
    } catch (error) {
      let err = error as BusinessError;
      Logger.error(TAG, `initCamera fail: ${JSON.stringify(err)}`);
    }
  }

  isVideoFrameSupportedFn(videoFrame: number): boolean {
    let videoProfile: camera.VideoProfile | undefined = this.videoProfiles.find((videoProfile: camera.VideoProfile) => {
      return videoProfile.size.height === this.videoProfileObj.size.height &&
        videoProfile.size.width === this.videoProfileObj.size.width &&
        videoProfile.format === this.videoProfileObj.format &&
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
    let session: camera.PortraitPhotoSession | camera.CaptureSession = this.getSession();
    if (!session) {
      return;
    }
    let isSupported: boolean = false;
    isSupported = session.isExposureModeSupported(aeMode);
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
    session.setExposureMode(aeMode);
    let exposureMode: camera.ExposureMode | undefined = undefined;
    exposureMode = session.getExposureMode();
    Logger.info(TAG, `getExposureMode success, exposureMode: ${exposureMode}`);
  }

  /**
   * 曝光区域
   */
  isMeteringPoint(point: camera.Point): void {
    // 获取当前曝光模式
    let session: camera.PortraitPhotoSession | camera.CaptureSession = this.getSession();
    if (!session) {
      return;
    }
    let exposureMode: camera.ExposureMode | undefined = undefined;
    exposureMode = session.getExposureMode();
    Logger.info(TAG, `getExposureMode success, exposureMode: ${exposureMode}`);
    session.setMeteringPoint(point);
    let exposurePoint: camera.Point | undefined = undefined;
    exposurePoint = session.getMeteringPoint();
    Logger.info(TAG, `getMeteringPoint exposurePoint: ${JSON.stringify(exposurePoint)}`);
  }

  /**
   * 曝光补偿
   */
  isExposureBiasRange(exposureBias: number): void {
    Logger.debug(TAG, `setExposureBias value ${exposureBias}`);
    // 查询曝光补偿范围
    let session: camera.PortraitPhotoSession | camera.CaptureSession = this.getSession();
    if (!session) {
      return;
    }
    let biasRangeArray: Array<number> = [];
    biasRangeArray = session.getExposureBiasRange();
    Logger.debug(TAG, `getExposureBiasRange success, biasRangeArray: ${JSON.stringify(biasRangeArray)}`);
    // 设置曝光补偿
    session.setExposureBias(exposureBias);
  }

  /**
   * 是否支持对应对焦模式
   */
  isFocusModeSupported(focusMode: camera.FocusMode): boolean {
    let session: camera.PortraitPhotoSession | camera.CaptureSession = this.getSession();
    if (!session) {
      return false;
    }
    return session.isFocusModeSupported(focusMode);
  }

  /**
   * 对焦模式
   */
  isFocusMode(focusMode: camera.FocusMode): void {
    // 检测对焦模式是否支持
    let isSupported = this.isFocusModeSupported(focusMode);
    Logger.info(TAG, `isFocusModeSupported isSupported: ${JSON.stringify(isSupported)}`);
    // 设置对焦模式
    if (!isSupported) {
      return;
    }
    let session: camera.PortraitPhotoSession | camera.CaptureSession = this.getSession();
    if (!session) {
      return;
    }
    session.setFocusMode(focusMode);
  }

  /**
   * 焦点
   */
  isFocusPoint(point: camera.Point): void {
    // 设置焦点
    let session: camera.PortraitPhotoSession | camera.CaptureSession = this.getSession();
    if (!session) {
      return;
    }
    session.setFocusPoint(point);
    Logger.info(TAG, 'setFocusPoint success');
    // 获取当前的焦点
    let nowPoint: camera.Point | undefined = undefined;
    nowPoint = session.getFocusPoint();
    Logger.info(TAG, `getFocusPoint success, nowPoint: ${JSON.stringify(nowPoint)}`);
  }

  /**
   * 闪关灯
   */
  hasFlashFn(flashMode: camera.FlashMode): void {
    let session: camera.PortraitPhotoSession | camera.CaptureSession = this.getSession();
    if (!session) {
      return;
    }
    // 检测是否有闪关灯
    let hasFlash = session.hasFlash();
    Logger.debug(TAG, `hasFlash success, hasFlash: ${hasFlash}`);
    // 检测闪光灯模式是否支持
    let isFlashModeSupported = session.isFlashModeSupported(flashMode);
    Logger.debug(TAG, `isFlashModeSupported success, isFlashModeSupported: ${isFlashModeSupported}`);
    // 设置闪光灯模式
    session.setFlashMode(flashMode);
    // 获取当前设备的闪光灯模式
    let nowFlashMode = session.getFlashMode();
    Logger.debug(TAG, `getFlashMode success, nowFlashMode: ${nowFlashMode}`);
  }

  getSession(): camera.PortraitPhotoSession | camera.CaptureSession | undefined {
    let session: camera.PortraitPhotoSession | camera.CaptureSession = undefined;
    if (this.isPortraitMode) {
      session = this.portraitSession;
    } else {
      session = this.captureSession;
    }
    return session;
  }

  /**
   * 变焦
   */
  setZoomRatioFn(zoomRatio: number): void {
    Logger.info(TAG, `setZoomRatioFn value ${zoomRatio}`);
    // 获取支持的变焦范围
    let session: camera.PortraitPhotoSession | camera.CaptureSession = this.getSession();
    if (!session) {
      return;
    }
    try {
      let zoomRatioRange = session.getZoomRatioRange();
      Logger.info(TAG, `getZoomRatioRange success: ${JSON.stringify(zoomRatioRange)}`);
    } catch (error) {
      let err = error as BusinessError;
      Logger.error(TAG, `getZoomRatioRange fail: ${JSON.stringify(err)}`);
    }

    try {
      session.setZoomRatio(zoomRatio);
      Logger.info(TAG, 'setZoomRatioFn success');
    } catch (error) {
      let err = error as BusinessError;
      Logger.error(TAG, `setZoomRatioFn fail: ${JSON.stringify(err)}`);
    }

    try {
      let nowZoomRatio = session.getZoomRatio();
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
    this.videoOutput = this.cameraManager.createVideoOutput(this.videoProfileObj, videoId);
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
      this.videoConfig.profile.videoFrameWidth = this.videoProfileObj.size.width;
      this.videoConfig.profile.videoFrameHeight = this.videoProfileObj.size.height;
      this.videoConfig.profile.videoFrameRate = this.videoProfileObj.frameRateRange.min;
      Logger.info(TAG, `deviceType: ${deviceType}, videoSourceType: ${JSON.stringify(this.videoConfig)}`);
      await this.videoRecorder.prepare(this.videoConfig).catch((err: { code?: number }): void => {
        Logger.error(TAG, `startVideo prepare err: ${JSON.stringify(err)}`);
      });
      let videoId = await this.videoRecorder.getInputSurface();
      Logger.debug(TAG, `startVideo videoProfileObj: ${JSON.stringify(this.videoProfileObj)}`);
      this.videoOutput = this.cameraManager.createVideoOutput(this.videoProfileObj, videoId);
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
    Logger.info(TAG, 'releaseCamera is called');
    if (this.previewOutput) {
      try {
        await this.previewOutput.stop();
        await this.previewOutput.release();
      } catch (error) {
        let err = error as BusinessError;
        Logger.error(TAG, `previewOutput release fail: error: ${JSON.stringify(err)}`);
      } finally {
        this.previewOutput = null;
      }

    }
    if (this.photoOutPut) {
      try {
        await this.photoOutPut.release();
      } catch (error) {
        let err = error as BusinessError;
        Logger.error(TAG, `photoOutPut release fail: error: ${JSON.stringify(err)}`);
      } finally {
        this.photoOutPut = null;
      }
    }
    if (this.videoOutput) {
      try {
        await this.videoOutput.release();
      } catch (error) {
        let err = error as BusinessError;
        Logger.error(TAG, `videoOutput release fail: error: ${JSON.stringify(err)}`);
      } finally {
        this.videoOutput = null;
      }
    }
    if (this.captureSession) {
      try {
        await this.captureSession.release();
      } catch (error) {
        let err = error as BusinessError;
        Logger.error(TAG, `captureSession release fail: error: ${JSON.stringify(err)}`);
      } finally {
        this.captureSession = null;
      }
    }
    if (this.portraitSession) {
      try {
        await this.portraitSession.release();
      } catch (error) {
        let err = error as BusinessError;
        Logger.error(TAG, `portraitSession release fail: error: ${JSON.stringify(err)}`);
      } finally {
        this.portraitSession = null;
      }
    }
    if (this.cameraInput) {
      try {
        await this.cameraInput.close();
      } catch (error) {
        let err = error as BusinessError;
        Logger.error(TAG, `cameraInput close fail: error: ${JSON.stringify(err)}`);
      } finally {
        this.cameraInput = null;
      }
    }
    Logger.info(TAG, 'releaseCamera success');
  }

  /**
   * 获取相机管理器实例
   */
  getCameraManagerFn(): void {
    if (this.cameraManager) {
      return;
    }
    try {
      this.cameraManager = camera.getCameraManager(globalThis.abilityContext);
      Logger.info(TAG, `getCameraManager success: ${this.cameraManager}`);
    } catch (error) {
      let err = error as BusinessError;
      Logger.error(TAG, `getCameraManager failed: ${JSON.stringify(err)}`);
    }
  }

  getModeManagerFn(): void {
    try {
      this.cameraManager = camera.getCameraManager(globalThis.abilityContext);
      Logger.info(TAG, `getModeManagerFn success: ${this.cameraManager}`);
    } catch (error) {
      let err = error as BusinessError;
      Logger.error(TAG, `getModeManagerFn failed: ${JSON.stringify(err)}`);
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

  getSupportedModeFn(cameraIndex: number): void {
    try {
      this.sceneModes = this.cameraManager.getSupportedSceneModes(this.cameras[cameraIndex]);
      Logger.info(TAG, `getSupportedModeFn success: ${this.sceneModes}, length: ${this.sceneModes.length}`);
    } catch (error) {
      let err = error as BusinessError;
      Logger.error(TAG, `getSupportedModeFn failed: ${JSON.stringify(err)}`);
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
  createPreviewOutputFn(photoProfileObj: camera.Profile, surfaceId: string): void {
    try {
      this.previewOutput = this.cameraManager.createPreviewOutput(photoProfileObj, surfaceId);
      Logger.info(TAG, `createPreviewOutput success: ${this.previewOutput}`);
    } catch (error) {
      let err = error as BusinessError;
      Logger.error(TAG, `createPreviewOutput failed: ${JSON.stringify(err)}`);
    }
  }

  /**
   * 创建photoOutPut输出对象
   */
  createPhotoOutputFn(photoProfileObj: camera.Profile, surfaceId: string): void {
    Logger.info(TAG, `createPhotoOutputFn photoProfiles: ${JSON.stringify(photoProfileObj)} ,captureMode: ${this.captureMode}`);
    switch (this.captureMode) {
      case 0:
        this.photoOutPut = this.cameraManager.createPhotoOutput(photoProfileObj, surfaceId);
        break;
      case 1:
      case 2:
        this.photoOutPut = this.cameraManager.createPhotoOutput(photoProfileObj);
        if (this.photoOutPut == null) {
          Logger.error(TAG, 'createPhotoOutputFn createPhotoOutput faild');
        }
        break;
    }
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
      if (AppStorage.get('deferredImage')) {
        this.isDeferredImageDeliverySupported(1);
        this.deferImageDeliveryFor(1);
        this.isDeferredImageDeliveryEnabled(1);
      }

      // 提交配置信息
      await this.captureSession.commitConfig();
      AppStorage.setOrCreate('colorEffectComponentIsHidden', this.getSupportedColorEffects().length > 0 ? false : true);
      AppStorage.setOrCreate('deferredPhotoComponentIsHidden', false);
      if (this.colorEffect) {
        this.setColorEffect(this.colorEffect);
      }
      // 开始会话工作
      await this.captureSession.start();
      this.isFocusMode(globalThis.settingDataObj.focusMode);
      Logger.info(TAG, 'sessionFlowFn success');
    } catch (error) {
      let err = error as BusinessError;
      Logger.error(TAG, `sessionFlowFn fail : ${JSON.stringify(err)}`);
    }
  }

  async portraitSessionFlowFn(sceneModeIndex: number): Promise<void> {
    try {
      // 创建PortraitSession实例
      this.portraitSession = this.cameraManager.createSession(camera.SceneMode.PORTRAIT_PHOTO);
      // 监听焦距的状态变化
      this.onFocusStateChange();
      // 监听拍照会话的错误事件
      this.onCaptureSessionErrorChange();
      // 开始配置会话
      this.portraitSession.beginConfig();
      // 把CameraInput加入到会话
      this.portraitSession.addInput(this.cameraInput);
      // 把previewOutput加入到会话
      this.portraitSession.addOutput(this.previewOutput);
      // 把photoOutPut加入到会话
      this.portraitSession.addOutput(this.photoOutPut);
      if (AppStorage.get('deferredImage')) {
        this.isDeferredImageDeliverySupported(1);
        this.deferImageDeliveryFor(1);
        this.isDeferredImageDeliveryEnabled(1);
      }

      // 提交配置信息
      await this.portraitSession.commitConfig();
      this.setPortraitEffect();
      AppStorage.setOrCreate('colorEffectComponentIsHidden', this.getSupportedColorEffects().length > 0 ? false : true);
      if (this.colorEffect) {
        this.setColorEffect(this.colorEffect);
      }
      // 开始会话工作
      await this.portraitSession.start();
      this.isFocusMode(globalThis.settingDataObj.focusMode);
      Logger.info(TAG, 'portraitSessionFlowFn success');
    } catch (error) {
      let err = error as BusinessError;
      Logger.error(TAG, `portraitSessionFlowFn fail : ${JSON.stringify(err)}`);
    }
  }

  setPortraitEffect(): void {
    try {
      this.portraitSession.setPortraitEffect(camera.PortraitEffect.CIRCLES);
    } catch (error) {
      let err = error as BusinessError;
      Logger.error(TAG, `setPortraitEffect error code: ${err.code}`);
    }
    this.getPortraitEffect();
  }

  getPortraitEffect(): void {
    try {
      let portraitEffect = this.portraitSession.getPortraitEffect();
      Logger.info(TAG, `getPortraitEffect portraitEffect: ${portraitEffect}`);
    } catch (error) {
      let err = error as BusinessError;
      Logger.error(TAG, `setPortraitEffect error code: ${err.code}`);
    }
  }

  setColorEffect(colorEffect: camera.ColorEffectType): void {
    Logger.info(TAG, 'setColorEffect is called.');
    if (this.captureSession || this.portraitSession) {
      let res: Array<camera.ColorEffectType> | undefined = [];
      res = this.getSupportedColorEffects();
      let session: camera.PortraitPhotoSession | camera.CaptureSession = this.getSession();
      if (!session) {
        return;
      }
      for (let i = 0; i < res.length; i++) {
        if (res[i] === colorEffect) {
          Logger.info(TAG, 'setColorEffect success.');
          session.setColorEffect(colorEffect);
          this.colorEffect = colorEffect;
          return;
        }
      }
      Logger.error(TAG, `setColorEffect fail: The colorEffect ${colorEffect} was not found`);
    }
  }

  getColorEffect(): camera.ColorEffectType | undefined {
    Logger.info(TAG, 'getColorEffect is called.');
    let colorEffect: camera.ColorEffectType | undefined = undefined;
    if (this.captureSession || this.portraitSession) {
      let session: camera.PortraitPhotoSession | camera.CaptureSession = this.getSession();
      if (!session) {
        return colorEffect;
      }
      try {
        colorEffect = session.getColorEffect();
      } catch (error) {
        let err = error as BusinessError;
        Logger.error(TAG, `setColorEffect fail: error code ${err.code}`);
      }
    }
    return colorEffect;
  }

  getSupportedColorEffects(): Array<camera.ColorEffectType> | undefined {
    Logger.info(TAG, 'getSupportedColorEffects is called.');
    let res: Array<camera.ColorEffectType> | undefined = [];
    if (this.captureSession || this.portraitSession) {
      let session: camera.PortraitPhotoSession | camera.CaptureSession = this.getSession();
      if (!session) {
        return res;
      }
      res = session.getSupportedColorEffects();
      Logger.info(TAG, `getSupportedColorEffects length: ${res.length}`);
    }
    return res;
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
    this.photoOutPut.on('error', (data: BusinessError): void => {
      Logger.info(TAG, `photoOutPut data: ${JSON.stringify(data)}`);
    });
    this.photoOutPut.on('photoAvailable', (err: BusinessError, photo: camera.Photo): void => {
      Logger.info(TAG, 'photoOutPutCallBack photoAvailable 3');
      if (err) {
        Logger.info(TAG, `photoAvailable error: ${JSON.stringify(err)}.`);
        return;
      }
      let mainImage: image.Image = photo.main;
      AppStorage.setOrCreate('mainImage', mainImage);
      mainImage.getComponent(image.ComponentType.JPEG, (errCode: BusinessError, component: image.Component): void => {
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
        this.savePicture(buffer, mainImage);
      });
      photo.release();
    });
    this.photoOutPut.on('deferredPhotoProxyAvailable', (err: BusinessError, proxyObj: camera.DeferredPhotoProxy): void => {
      if (err) {
        Logger.info(TAG, `deferredPhotoProxyAvailable error: ${JSON.stringify(err)}.`);
        return;
      }
      Logger.info(TAG, 'photoOutPutCallBack deferredPhotoProxyAvailable');
      proxyObj.getThumbnail().then((thumbnail: image.PixelMap) => {
        AppStorage.setOrCreate('proxyThumbnail', thumbnail);
      });
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
      Logger.info(TAG, `Preview output previewOutputError: ${JSON.stringify(previewOutputError)}`);
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
    Logger.info(TAG, 'onCameraStatusChange is called');
    this.cameraManager.on('cameraStatus', async (err: BusinessError, cameraStatusInfo: camera.CameraStatusInfo): Promise<void> => {
      Logger.info(TAG, `onCameraStatusChange cameraStatus success, cameraId: ${cameraStatusInfo.camera.cameraId}, status: ${cameraStatusInfo.status}`);
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
    let session: camera.PortraitPhotoSession | camera.CaptureSession = this.getSession();
    if (!session) {
      return;
    }
    session.on('focusStateChange', (err: BusinessError, focusState: camera.FocusState): void => {
      Logger.info(TAG, `onFocusStateChange captureSession focusStateChange success : ${focusState}`);
    });
  }

  /**
   * 监听拍照会话的错误事件
   */
  onCaptureSessionErrorChange(): void {
    let session: camera.PortraitPhotoSession | camera.CaptureSession = this.getSession();
    if (!session) {
      return;
    }
    session.on('error', (captureSessionError: BusinessError): void => {
      Logger.info(TAG, 'onCaptureSessionErrorChange captureSession fail: ' + JSON.stringify(captureSessionError.code));
    });

  }

  setCaptureMode(mode: number): void {
    this.captureMode = mode;
  }

  getCaptureMode(): boolean {
    return this.captureMode;
  }

  /**
   * 查询是否支持二阶段
   */
  isDeferredImageDeliverySupported(num: number): boolean {
    let res: boolean = false;
    Logger.info(TAG, `isDeferredImageDeliverySupported type: ${num % 2}`);
    if (this.photoOutPut !== null && num % 2 === 0) {
      res = this.photoOutPut.isDeferredImageDeliverySupported(camera.DeferredDeliveryImageType.NONE);
    } else {
      res = this.photoOutPut.isDeferredImageDeliverySupported(camera.DeferredDeliveryImageType.PHOTO);
    }
    Logger.info(TAG, `isDeferredImageDeliverySupported res: ${res}`);
  }


  /**
   * 查询是否已使能二阶段
   */
  isDeferredImageDeliveryEnabled(num: number): boolean {
    let res: boolean = false;
    Logger.info(TAG, `IsDeferredImageDeliveryEnabled type: ${num % 2}`);
    if (this.photoOutPut !== null && num % 2 === 0) {
      res = this.photoOutPut.isDeferredImageDeliveryEnabled(camera.DeferredDeliveryImageType.NONE);
    } else {
      res = this.photoOutPut.isDeferredImageDeliveryEnabled(camera.DeferredDeliveryImageType.PHOTO);
    }
    Logger.info(TAG, `IsDeferredImageDeliveryEnabled res: ${res}`);
    return res;
  }

  /**
   * 使能二阶段
   */
  deferImageDeliveryFor(num: number): void {
    Logger.info(TAG, `deferImageDeliveryFor type: ${num}`);
    this.photoOutPut.deferImageDeliveryFor(camera.DeferredDeliveryImageType.PHOTO);
  }
}

export default new CameraService();

