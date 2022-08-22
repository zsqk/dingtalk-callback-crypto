import { assertEquals } from 'https://deno.land/std@0.152.0/testing/asserts.ts';
import { DingtalkCallbackCrypto } from './mod.ts';

const TOKEN = 'aaaqo3IDtbgWd4uyJYtrzzz';
const ENCODING_AES_KEY = 'aaabWe22zMdfpVVF6kFsZ9E4ODL1wjjykB5ifzjLzzz';
const APPKEY = 'dingn4jxcg1w9jy9exxx';

Deno.test('decrypt-1', async () => {
  const dcc = new DingtalkCallbackCrypto({
    keyStr: ENCODING_AES_KEY,
    token: TOKEN,
    appkey: APPKEY,
  });
  const res = await dcc.decrypt(
    'cKVPF3fvpb646ZnKPbYn/Y5fChYt4e3OjgLbwuMSMm7fuv/Sfu0POorlMHTLide0mitKXnWk1hs/ON7onS9WcQ==',
  );

  assertEquals(res.appKey, APPKEY);
  assertEquals(res.jsonStr, 'success');
});

Deno.test('decrypt-2', async () => {
  const d =
    `cKVPF3fvpb646ZnKPbYn/bhwggCKWyF+4H4aqPLqmhD1wT7TKRRjHaRJs9/KcAK2oiiCeYS6FV30KJQoKDFmqg==`;
  const dcc = new DingtalkCallbackCrypto({
    keyStr: ENCODING_AES_KEY,
    token: TOKEN,
    appkey: APPKEY,
  });
  const res = await dcc.decrypt(d);
  console.log(
    res,
    res.jsonStr,
    res.jsonStr.length,
    res.appKey,
    res.appKey.length,
  );

  assertEquals(res.appKey, APPKEY);
  assertEquals(res.jsonStr, '中文测试');
});
