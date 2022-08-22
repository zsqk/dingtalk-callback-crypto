import {
  decode,
  encode,
} from 'https://deno.land/std@0.151.0/encoding/base64.ts';
import { Aes } from 'https://deno.land/x/crypto@v0.10.0/aes.ts';
import { Cbc } from 'https://deno.land/x/crypto@v0.10.0/block-modes.ts';
import {
  intToU8a,
  u8aToInt,
} from 'https://deno.land/x/somefn@v0.14.0/js/int.ts';
import { genRandomString } from 'https://deno.land/x/somefn@v0.14.0/js/str.ts';
import { hashString } from 'https://deno.land/x/somefn@v0.14.0/js/hash.ts';

/**
 * 钉钉事件回调加解密
 *
 * @author Lian Zheren <lzr@go0356.com>
 */
export class DingtalkCallbackCrypto {
  /**
   * 钉钉后台设置回调时填写的 `aes_key`
   */
  private readonly aeskeyStr: string;

  /**
   * 钉钉后台设置回调时填写的 `token`
   */
  private readonly token: string;

  /**
   * 开放平台应用的 `AppKey`
   */
  private readonly appkey: string;

  constructor(opt: { keyStr: string; token: string; appkey: string }) {
    this.aeskeyStr = opt.keyStr;
    this.token = opt.token;
    this.appkey = opt.appkey;
  }

  /**
   * 解密方法
   * @param dataStr 需要解密的信息 (base64 编码)
   * @returns 解密后的数据 内部字符串为 UTF-8
   */
  public decrypt(dataStr: string): Promise<{
    jsonStr: string;
    appKey: string;
  }> {
    return decryptDingtalk(this.aeskeyStr, dataStr);
  }

  /**
   * 加密方法
   * @param dataStr 需要加密的字符串 (UTF-8)
   * @returns 加密后的数据 (base64 编码)
   */
  public encrypt(dataStr: string): Promise<string> {
    return encryptDingtalk(this.appkey, this.aeskeyStr, dataStr);
  }

  /**
   * 生成需要返回给钉钉的数据
   * @param dataStr 需要加密的字符串 (UTF-8)
   * @returns 钉钉所需的数据 (钉钉文档中要求的结构)
   */
  public async genReturnData(
    dataStr: string,
    timestamp: string = Date.now().toString(),
  ): Promise<{
    msg_signature: string;
    timeStamp: string;
    nonce: string;
    encrypt: string;
  }> {
    const encryptedStr = await this.encrypt(dataStr);
    const nonce = genRandomString(5, 'abcdefghijkmnpqrstuvwxyz23456789');
    const msgSignature = await genSignature(
      this.token,
      timestamp,
      nonce,
      encryptedStr,
    );
    return {
      msg_signature: msgSignature,
      timeStamp: timestamp,
      nonce,
      encrypt: encryptedStr,
    };
  }
}

/**
 * 解密钉钉加密的数据
 * https://open.dingtalk.com/document/orgapp-server/configure-event-subcription
 *
 * @param keyStr
 * @param dataStr
 * @returns
 *
 * @author Lian Zheren <lzr@go0356.com>
 */
function decryptDingtalk(
  keyStr: string,
  dataStr: string,
): Promise<{
  jsonStr: string;
  appKey: string;
}> {
  const key = decode(keyStr);
  const iv = key.slice(0, 16);

  const decipher = new Cbc(Aes, key, iv);
  const decrypted = decipher.decrypt(decode(dataStr));

  // 计算需要加密信息的长度
  const l = u8aToInt(decrypted.slice(16, 20));

  // 获取加密的信息
  const jsonStr = new TextDecoder().decode(decrypted.slice(20, 20 + l));

  // 钉钉自定义的补充信息 (不符合 AES-CBC 标准)
  let pad = decrypted.slice(-1)[0];
  // 钉钉补充权限的, 根据权限, 补充 pad, pad 特点是长度与值一致
  for (let i = decrypted.length - 1; i > decrypted.length - 1 - pad; i--) {
    if (decrypted[i] !== pad) {
      pad = 0;
      break;
    }
  }
  const appKey = new TextDecoder().decode(decrypted.slice(20 + l, -pad));

  return Promise.resolve({ jsonStr, appKey });
}

/**
 * 加密数据以回传给钉钉
 * https://open.dingtalk.com/document/orgapp-server/configure-event-subcription
 *
 * @param appkey
 * @param keyStr
 * @param dataStr
 * @returns
 *
 * @author Lian Zheren <lzr@go0356.com>
 */
async function encryptDingtalk(
  appkey: string,
  keyStr: string,
  dataStr: string,
) {
  const u8aKey = decode(keyStr);

  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    u8aKey,
    {
      name: 'AES-CBC',
    },
    false,
    ['encrypt', 'decrypt'],
  );

  const pre = new TextEncoder().encode(genRandomString(16));
  const len = intToU8a(dataStr.length, { l: 4 });
  const data = new TextEncoder().encode(dataStr + appkey);

  const iv = u8aKey.slice(0, 16);
  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-CBC', iv },
    cryptoKey,
    new Uint8Array([...pre, ...len, ...data]),
  );

  return encode(encrypted);
}

/**
 * 生成签名
 *
 * @author Lian Zheren <lzr@go0356.com>
 */
async function genSignature(
  dingtalkToken: string,
  timestamp: string,
  nonce: string,
  encryptRes: string,
) {
  const strArr = [dingtalkToken, timestamp, nonce, encryptRes];
  strArr.sort();
  const msgSignature = await hashString('SHA-1', strArr.join(''));
  return msgSignature;
}
