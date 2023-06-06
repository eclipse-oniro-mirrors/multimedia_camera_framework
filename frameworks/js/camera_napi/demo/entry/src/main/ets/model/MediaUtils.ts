// @ts-nocheck
/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

import mediaLibrary from '@ohos.multimedia.mediaLibrary';
import DateTimeUtil from '../model/DateTimeUtil';
import Logger from '../model/Logger';

const TAG: string = 'MediaUtils';

export default class MediaUtils {
  private mediaTest: mediaLibrary.MediaLibrary = mediaLibrary.getMediaLibrary(globalThis.abilityContext);
  private static instance: MediaUtils = new MediaUtils();
  private num: number = 0;

  public static getInstance(): MediaUtils {
    if (this.instance === undefined) {
      this.instance = new MediaUtils();
    }
    return this.instance;
  }

  async createAndGetUri(mediaType: number): Promise<mediaLibrary.FileAsset> {
    let info = this.getInfoFromType(mediaType);
    let dateTimeUtil = new DateTimeUtil();
    let name = `${dateTimeUtil.getDate()}_${dateTimeUtil.getTime()}`;
    let displayName = `${info.prefix}${name}${info.suffix}`;
    Logger.info(TAG, `createAndGetUri displayName = ${displayName}, mediaType = ${mediaType}`);
    let publicPath = await this.mediaTest.getPublicDirectory(info.directory);
    Logger.debug(TAG, `createAndGetUri publicPath = ${publicPath}`);
    try {
      return await this.mediaTest.createAsset(mediaType, displayName, publicPath);
    } catch {
      this.num++;
      displayName = `${info.prefix}${name}_${this.num}${info.suffix}`;
      return await this.mediaTest.createAsset(mediaType, displayName, publicPath);
    }
  }

  async queryFile(fileAsset: mediaLibrary.FileAsset): Promise<mediaLibrary.FileAsset> {
    let fileKeyObj = mediaLibrary.FileKey;
    if (fileAsset !== undefined) {
      let args = fileAsset.id.toString();
      let fetchOp: mediaLibrary.MediaFetchOptions = {
        selections: `${fileKeyObj.ID}=?`,
        selectionArgs: [args],
      };
      const fetchFileResult: mediaLibrary.FetchFileResult = await this.mediaTest.getFileAssets(fetchOp);
      Logger.info(TAG, `fetchFileResult.getCount() = ${fetchFileResult.getCount()}`);
      const fileAssets: Array<FileAsset> = await fetchFileResult.getAllObject();
      if (fileAssets.length) {
        return fileAssets[0];
      }
    }
    return undefined;
  }

  async getFdPath(fileAsset: mediaLibrary.FileAsset): Promise<number> {
    let fd: number = await fileAsset.open('Rw');
    Logger.info(TAG, `fd = ${fd}`);
    return fd;
  }

  async createFile(mediaType: number): Promise<number> {
    let fileAsset = await this.createAndGetUri(mediaType);
    if (fileAsset) {
      fileAsset = await this.queryFile(fileAsset);
      if (fileAsset) {
        let fd = await this.getFdPath(fileAsset);
        return fd;
      }
    }
    return undefined;
  }

  async getFileAssetsFromType(mediaType: number): Promise<mediaLibrary.FileAsset> {
    Logger.info(TAG, `getFileAssetsFromType,mediaType = ${mediaType}`);
    let fileKeyObj = mediaLibrary.FileKey;
    let fetchOp = {
      selections: `${fileKeyObj.MEDIA_TYPE}=?`,
      selectionArgs: [`${mediaType}`],
    };
    const fetchFileResult = await this.mediaTest.getFileAssets(fetchOp);
    Logger.info(TAG, `getFileAssetsFromType,fetchFileResult.count = ${fetchFileResult.getCount()}`);
    let fileAssets = [];
    if (fetchFileResult.getCount() > 0) {
      fileAssets = await fetchFileResult.getAllObject();
    }
    return fileAssets;
  }

  async getAlbums(): Promise<Array<{
    albumName: string,
    count: number,
    mediaType: mediaLibrary.MediaType
  }>> {
    Logger.info(TAG, 'getAlbums begin');
    let albums = [];
    const [files, images, videos, audios] = await Promise.all([
      this.getFileAssetsFromType(mediaLibrary.MediaType.FILE),
      this.getFileAssetsFromType(mediaLibrary.MediaType.IMAGE),
      this.getFileAssetsFromType(mediaLibrary.MediaType.VIDEO),
      this.getFileAssetsFromType(mediaLibrary.MediaType.AUDIO)
    ]);
    albums.push({
      albumName: 'Documents', count: files.length, mediaType: mediaLibrary.MediaType.FILE
    });
    albums.push({
      albumName: 'Pictures', count: images.length, mediaType: mediaLibrary.MediaType.IMAGE
    });
    albums.push({
      albumName: 'Camera', count: videos.length, mediaType: mediaLibrary.MediaType.VIDEO
    });
    albums.push({
      albumName: 'Audios', count: audios.length, mediaType: mediaLibrary.MediaType.AUDIO
    });
    return albums;
  }

  deleteFile(media: mediaLibrary.FileAsset): void {
    let uri = media.uri;
    Logger.info(TAG, `deleteFile,uri = ${uri}`);
    return this.mediaTest.deleteAsset(uri);
  }

  onDateChange(callback: () => void): void {
    this.mediaTest.on('albumChange', () => {
      Logger.info(TAG, 'albumChange called');
      callback();
    });
    this.mediaTest.on('imageChange', () => {
      Logger.info(TAG, 'imageChange called');
      callback();
    });
    this.mediaTest.on('audioChange', () => {
      Logger.info(TAG, 'audioChange called');
      callback();
    });
    this.mediaTest.on('videoChange', () => {
      Logger.info(TAG, 'videoChange called');
      callback();
    });
    this.mediaTest.on('fileChange', () => {
      Logger.info(TAG, 'fileChange called');
      callback();
    });
  }

  offDateChange(): void {
    this.mediaTest.off('albumChange');
    this.mediaTest.off('imageChange');
    this.mediaTest.off('audioChange');
    this.mediaTest.off('videoChange');
    this.mediaTest.off('fileChange');
  }

  /**
   * 照片格式
   */
  onChangePhotoFormat(): string {
    if (globalThis.settingDataObj.photoFormat === 0) {  // 图片格式: 0代表png图片格式
      return 'png';
    }
    if (globalThis.settingDataObj.photoFormat === 1) {  // 图片格式: 1代表jpg图片格式
      return 'jpg';
    }
    if (globalThis.settingDataObj.photoFormat === 2) {  // 图片格式: 2代表bmp图片格式
      return 'bmp';
    }
    if (globalThis.settingDataObj.photoFormat === 3) {  // 图片格式: 3代表webp图片格式
      return 'webp';
    }
    if (globalThis.settingDataObj.photoFormat === 4) {  // 图片格式: 4代表jpeg图片格式
      return 'jpeg';
    }
    return undefined;
  }

  getInfoFromType(mediaType: number): void {
    let result = {
      prefix: '', suffix: '', directory: 0
    };
    switch (mediaType) {
      case mediaLibrary.MediaType.FILE:
        result.prefix = 'FILE_';
        result.suffix = '.txt';
        result.directory = mediaLibrary.DirectoryType.DIR_DOCUMENTS;
        break;
      case mediaLibrary.MediaType.IMAGE:
        result.prefix = 'IMG_';
        result.suffix = `.${this.onChangePhotoFormat()}`;
        result.directory = mediaLibrary.DirectoryType.DIR_CAMERA;
        break;
      case mediaLibrary.MediaType.VIDEO:
        result.prefix = 'VID_';
        result.suffix = '.mp4';
        result.directory = mediaLibrary.DirectoryType.DIR_CAMERA;
        break;
      case mediaLibrary.MediaType.AUDIO:
        result.prefix = 'AUD_';
        result.suffix = '.wav';
        result.directory = mediaLibrary.DirectoryType.DIR_AUDIO;
        break;
    }
    return result;
  }
}