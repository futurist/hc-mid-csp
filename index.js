require('array-flat-polyfill')
const url = require('url')
const csp = require('helmet-csp')
const _ = require('lodash')
const {text} = require('get-body')
const uuidv4 = require('uuid/v4')
const cspParser = require('content-security-policy-parser')
const camelcase = require('camelcase')
const replaceString = require('replace-string')
const useragent = require('useragent')
const mime = require('mime')
const check = require('./check')
const {isArray} = Array

function parseCSPString(str) {
    if(isArray(str)) str = str.join('')
    const obj = {}
    _.forEach(cspParser(str || ''), (v,k) => {
        k = camelcase(k)
        if(k==='reportUri' && isArray(v)) v = v[0] || false
        if(isArray(v) && v.length==0) v = true
        obj[k] = v
    })
    return obj
}

module.exports = (app, appConfig) => {
    if(appConfig.cspString) {
        console.log('[hc-mid-csp] use config.cspString as directives')
    }
    const options = _.merge({
        override: [],
        browser: {},
        ignore: [],
        force: [],
        accepts: 'text/html',
        // generate `child-src` using frameSrc + workerSrc
        generateChildSrc: true,
        // generate http:// for https://
        generateMixed: {
            mediaSrc: true,
            imgSrc: true
        },
        // Specify directives as normal.
        directives: {
            // defaultSrc: ["'self'", 'default.com'],
            // scriptSrc: ["'self'", "'unsafe-inline'"],
            // styleSrc: ['style.com'],
            // fontSrc: ["'self'", 'fonts.com'],
            // imgSrc: ['img.com', 'data:'],
            // sandbox: ['allow-forms', 'allow-scripts'],
            // reportUri: '/report-violation',
            // objectSrc: ["'none'"],
            // upgradeInsecureRequests: true,
            // workerSrc: false // This is not set.
            reportUri: '${prefix}/__csp__'
        },

        // This module will detect common mistakes in your directives and throw errors
        // if it finds any. To disable this, enable "loose mode".
        loose: false,

        // Set to true if you only want browsers to report errors, not block them.
        // You may also set this to a function(req, res) in order to decide dynamically
        // whether to use reportOnly mode, e.g., to allow for a dynamic kill switch.
        reportOnly: false,

        // Set to true if you want to blindly set all headers: Content-Security-Policy,
        // X-WebKit-CSP, and X-Content-Security-Policy.
        setAllHeaders: false,

        // Set to true if you want to disable CSP on Android where it can be buggy.
        disableAndroid: false,

        // Set to false if you want to completely disable any user-agent sniffing.
        // This may make the headers less compatible but it will be much faster.
        // This defaults to `true`.
        browserSniff: true
    }, _.omit(appConfig, 'directives'), {
        directives: appConfig.cspString
            ? parseCSPString(appConfig.cspString)
            : appConfig.directives
    })

    // replace ${nonce} with function
    _.forEach(options.directives, (rule, name, obj)=>{
        if(typeof rule==='string') rule = obj[name] = [obj[name]]
        if(!isArray(rule) || name==='reportUri') return
        _.forEach(rule, (v,key,obj)=>{
            if(typeof v==='string') {
                obj[key] = (req, res) => {
                    const uaString = req.headers['user-agent']
                    const uaObj = useragent.parse(uaString)
                    let ret = v.replace('${nonce}', res.locals.cspNonce)
                    // const userAgent = useragent.parse(req.headers['user-agent'])
                    // safari don't support 'report-sample'
                    // if(/Safari/i.test(userAgent.family)){
                    //     ret = ret.replace("'report-sample'", '')
                    // }
                    const allEntry = check(options.override, req.path, req.method, 'filter');
                    allEntry
                    .sort((a,b)=>((a.find(isObject)||{}).order||0) - ((b.find(isObject)||{}).order||0))
                    .forEach((entry) => {
                        const opt = entry.find(isObject)
                        if(opt) {
                            const remove = [].concat(
                                _.get(opt, 'remove.'+name) || [],
                                _.get(options.browser, uaObj.family+'.remove.'+name) || []
                            ).flatMap(v=>v.split(/\s+/))
                            const add = [].concat(
                                _.get(opt, 'add.'+name) || [],
                                _.get(options.browser, uaObj.family+'.add.'+name) || []
                            ).flatMap(v=>v.split(/\s+/))
                            ret = remove.reduce((ret,c)=>replaceString(ret, c, ''), ret)
                            ret = add.concat(ret).join(' ')
                        }
                    });

                    const otherProtocol = findOtherProtocol(req.protocol)
                    if(options.generateMixed[name] && otherProtocol) {
                        ret = ret.split(/\s+/).map(x=>{
                            x = x.trim()
                            if(x[0]!="'" && !x.endsWith(':') && x.indexOf('.')>-1 && isProtoless(x)) {
                                const arr = []
                                const newX = `${otherProtocol}://${x}`
                                x = `${req.protocol}://${x}`
                                if(ret.indexOf(x)<0) {
                                    arr.push(x)
                                }
                                if(ret.indexOf(newX)<0) {
                                    arr.push(newX)
                                }
                                x = arr.join(' ')
                            }
                            return x
                        }).join(' ')
                    }

                    ret = ret.trim();

                    if(ret && ret !== "'none'") {
                        ret = replaceString(ret, "'none'", '')
                    }

                    return ret
                }
            }
        })
    })
    
    // get app prefix
    const prefix = app.options.prefix || ''
    
    // normalize reportUri
    const reportUri = [].concat(options.directives.reportUri)
        .filter(v=>typeof v==='string')
        .flatMap(v=>v.split(/\s+/))
        .map(v=>v.replace('${prefix}', prefix))

    // check local router
    let localReports = reportUri
        .filter(uri => isProtoless(uri))
    const strReports = reportUri.join(' ')

    // disable reportUri if it's empty
    options.directives.reportUri = strReports || false

    if(options.generateChildSrc && !_.isEmpty(options.directives.workerSrc)) {
        const childSrc = [].concat(options.directives.workerSrc, options.directives.frameSrc).filter(Boolean)
        if(childSrc.length>0) {
            options.directives.childSrc = childSrc
        }
    }

    const cspMiddleware = csp(options)
    
    console.log('csp report config:', options)
    if(localReports.some(uri => !uri.startsWith('/'))) {
        throw new Error('local reportUri must starts with /, but value is:' + reportUri)
    }

    return (req, res, next) => {
        const signature = req.headers['signature']
        const uaString = req.headers['user-agent']
        const uaObj = useragent.parse(uaString)
        const apiIndex = localReports.indexOf(prefix + req.path)
        const isIgnore = req.xhr || check(options.ignore, req.path, req.method)
        const contentType = res.get('Content-Type') || mime.getType(req.path)
        const isForce = check(options.force, req.path, req.method)
        if(apiIndex >= 0 && isCSPPost(req)) {
            text(req, req.headers).then(val=>{
                const json = JSON.parse(val)
                console.log('csp-report:', json)
                console.log('user-agent:', uaString)
                if(typeof options.onReport === 'function'){
                    options.onReport({
                        app,
                        config: appConfig,
                        text: val,
                        json,
                        ua: uaObj,
                        req,
                        res
                    })
                }
                res.status(204).end()
            }).catch(err=>{
                console.log('csp-report err:', err)
                next(err)
            })
        } else if(
            isForce || (
                !isIgnore
                && uaString && uaObj != null && uaObj.family
                && !/HttpClient/i.test(uaObj.family)
                && !signature
                && req.accepts(options.accepts)
                && (!contentType || String(contentType).indexOf(mime.getType(options.accepts))>-1)
            )
        ) {
            const nonce = res.locals.cspNonce = uuidv4().replace(/-/g, '')
            res.set('x-csp-nonce', nonce)
            cspMiddleware(req, res, next)
        } else {
            next()
        }
    }
}

function hasAccepts(req) {
    return req.headers.accept && req.headers.accept != '*/*'
}

function isCSPPost(req){
    return req.method === 'POST' && (req.get('content-type')||'').indexOf('csp-report') > 0
}

function isObject(val) {
    return typeof val==='object' && val
}

function isProtoless (tUrl) {
    const parsed = url.parse(tUrl)
    return !parsed.protocol && !!parsed.pathname
}

function findOtherProtocol (protocol) {
    switch(protocol) {
        case 'http': return 'https'
        case 'https': return 'http'
        case 'wss': return 'ws'
        case 'ws': return 'wss'
        default: return
    }
}
