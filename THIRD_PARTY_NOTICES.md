# Third-party notices

TrustProbe is MIT licensed ([LICENSE](LICENSE)). It includes or links the components below. The
native ones are built from the `app/src/main/jni/hev-socks5-tunnel` git submodule, unmodified; the
license texts are copied from the LICENSE files in that tree (and, for Bouncy Castle, from the jar).

| Component | Version / commit | License | In the APK |
|---|---|---|---|
| [hev-socks5-tunnel](https://github.com/heiher/hev-socks5-tunnel) | 2.20.0 (`75dbc1e9ace6c70d3d1b94df7c283efe1de7effc`) | MIT | yes, `libhev-socks5-tunnel.so` |
| [hev-socks5-core](https://github.com/heiher/hev-socks5-core) (submodule `src/core`) | `b43fa857fb39c854da01d13bc55eded66b4f4a3b` | MIT | yes, linked into the above |
| [hev-task-system](https://github.com/heiher/hev-task-system) (submodule `third-part/hev-task-system`) | 5.12.0 (`ded55c412b3951bc7decb5cb3b9135701e762998`) | MIT | yes, linked into the above |
| [lwIP](https://github.com/heiher/lwip), a branch of [lwIP](https://savannah.nongnu.org/projects/lwip/) (submodule `third-part/lwip`) | 2.2.1.12 (`8115cd6150ab32500db3d4d8bd8ad7ec6648534c`) | BSD-3-Clause | yes, linked into the above |
| [yaml](https://github.com/heiher/yaml), a branch of [libyaml](https://github.com/yaml/libyaml) (submodule `third-part/yaml`) | 0.2.5.4 (`0c82efd10dc67b9e7f159d2c7f5d1dc3c1b5bc11`) | MIT | yes, linked into the above |
| Bouncy Castle (`bcpkix-jdk18on`, `bcprov-jdk18on`) | 1.87 | MIT (Bouncy Castle License) | yes |
| AndroidX, Jetpack Compose, Room, Kotlin standard library, kotlinx.coroutines, kotlinx.serialization | see `gradle/libs.versions.toml` | Apache-2.0 | yes |
| OkHttp | 5.5.1 | Apache-2.0 | testbed app only |

Notes:

- lwIP's tree also carries PPP sources with other notices (Carnegie Mellon, PolarSSL and others).
  They are compiled out: `PPP_SUPPORT` is 0 (the default in `ppp_opts.h`) and hev-socks5-tunnel
  does not enable it.
- The submodule also contains `third-part/wintun` (prebuilt Windows binaries under their own
  license). It is used only by the Windows build of hev-socks5-tunnel and is not part of the APK.
- The Apache-2.0 components are distributed under the Apache License, Version 2.0:
  <https://www.apache.org/licenses/LICENSE-2.0>.

## hev-socks5-tunnel, hev-socks5-core, hev-task-system, yaml

Each of the four LICENSE files reads:

```text
Copyright (c) 2022 hev

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

The yaml branch is derived from libyaml, which is also MIT licensed (copyright Ingy döt Net and
Kirill Simonov); see <https://github.com/yaml/libyaml/blob/master/License>.

## lwIP

```text
Copyright (c) 2001, 2002 Swedish Institute of Computer Science.
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.
3. The name of the author may not be used to endorse or promote products
   derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
OF SUCH DAMAGE.
```

## Bouncy Castle

From `META-INF/LICENSE.md` in `bcprov-jdk18on-1.87.jar`:

```text
MIT License (https://opensource.org/licenses/MIT)

Copyright (c) 2000-2026 The Legion of the Bouncy Castle Inc. (https://www.bouncycastle.org).
Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
associated documentation files (the "Software"), to deal in the Software without restriction,
including without limitation the rights to use, copy, modify, merge, publish, distribute,
sub license, and/or sell copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions: The above copyright notice and this
permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT
NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT
OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
```
