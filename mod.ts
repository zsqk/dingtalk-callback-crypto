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
   * 开放平台应用的 `AppKey`
   */
  private readonly appkey: string;

  constructor(opt: { keyStr: string; appkey: string }) {
    this.aeskeyStr = opt.keyStr;
    this.appkey = opt.appkey;
  }

  /**
   * 解密方法
   * @param dataStr 需要解密的信息 (base64 编码)
   * @returns
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
   * @returns
   */
  public encrypt(dataStr: string): Promise<string> {
    return encryptDingtalk(this.appkey, this.aeskeyStr, dataStr);
  }
}

// https://open.dingtalk.com/document/orgapp-server/configure-event-subcription
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
  const decryptedStr = new TextDecoder().decode(decrypted.slice(20));
  const jsonStr = decryptedStr.slice(0, l);
  const appKey = decryptedStr.slice(l);

  return Promise.resolve({ jsonStr, appKey });
}

// https://open.dingtalk.com/document/orgapp-server/configure-event-subcription
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
