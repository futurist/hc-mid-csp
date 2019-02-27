# hc-mid-csp

[hc-bee](https://github.com/node-honeycomb/hc-bee) middleware to add csp headers

### install

```sh
npm i -S hc-mid-csp
```

### usage

`config` options see [helmet-csp](https://github.com/helmetjs/csp), with below different:

- add `cspString` option to allow set `CSP` content directly, if empty, fallback to `directives`
- `directives` also allow `string` type value, to prevent merge config of `hc-bee`
- `${prefix}` and `${nonce}` can be put into string as placeholder
- `directives.reportUri` default value: `${prefix}/__csp__`
- `res.locals.cspNonce` contains the `nonce` value
- add `x-csp-nonce` headers

### example

```js
middlewareConfig = {
    csp: {
        enable: true,
        module: './csp',
        config: {
            reportOnly: true,
            cspString: ``,
            directives: {
            "defaultSrc": "'none'",
            "baseUri": "'none'",
            "blockAllMixedContent": true,
            "connectSrc": "'self' g.alicdn.com",
            "fontSrc": "'self' data: at.alicdn.com g.alicdn.com",
            "formAction": "'self'",
            "frameAncestors": "'none'",
            "frameSrc": "'self' g.alicdn.com",
            "imgSrc": "'self' data: img.alicdn.com",
            "objectSrc": "'none'",
            "manifestSrc": "'self'",
            "mediaSrc": "'none'",
            "scriptSrc": "'report-sample' 'nonce-${nonce}' 'unsafe-inline' 'self' s.tianchi.aliyun.com"
            }
        }
    }
}
```

