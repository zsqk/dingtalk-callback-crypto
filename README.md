# dingtalk-callback-crypto

钉钉回调加解密类库 for deno

- [ ] 因为钉钉回调加密采用了不正规的解密方法, 导致无法使用 Web Crypto 进行解密.
      所以暂时使用了第三方库. 等待钉钉修正为正规加密方法, 改为 Web Crypto 解密.

关于钉钉的加密不规范, 再补充一句: Node.js 解密时,
正常都是先调用 `.update()` 方法, 再调用 `.final()` 方法,
可是如果处理钉钉加密的信息, 可以调用 `.update()` 方法,
但如果调用 `.final()` 方法, Node.js 则会报错.

从第三方的钉钉加解密 Node.js 库也能看出, 若要符合钉钉加密, 则不能按照正常流程走.
需要先按照如下方法在数据的末尾自行补充后再进行加密:

```ts
const padCount = 32 - (datau8asize % 32);
const padBuf = new Uint8Array(padCount).fill(padCount);
```

然后调用 `.setAutoPadding(false)` 避免系统自动补全. 如此之后, 完成加密.

大概就是 AES-CBC 加密需要特定的 byte 块, 而这个大小应该是 32,
所以如果需要加密的数据不是 32 的倍数, 则自动补充. 但这样魔改的方法属实没必要,
平白增加了不兼容性.

经查, <https://www.ietf.org/rfc/rfc3602.txt> 中说:

> The AES uses a block size of sixteen octets (128 bits).

虽然不限制填充什么, 但是限制必须为 128 位. 钉钉自定义补充的是 32 字节, 256 位.
从 block size 上看, 钉钉补充的似乎也不会导致解密失败.

虽然没找到根本原因, 但钉钉额外 padding 的数据也会导致直接做块解密的拿到不必要的
数据, 这种不标准的 padding 可能正是导致 Web Crypto 失败的原因.
