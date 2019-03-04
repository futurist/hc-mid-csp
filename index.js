require('array-flat-polyfill')
const csp = require('helmet-csp')
const _ = require('lodash')
const {json} = require('get-body')
const uuidv4 = require('uuid/v4')
const cspParser = require('content-security-policy-parser')
const camelcase = require('camelcase')
const replaceString = require('replace-string')
const useragent = require('useragent')
const mime = require('mime')
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
        accepts: 'text/html',
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
        const remove = _.get(options, 'remove.'+name) || []
        _.forEach(rule, (v,key,obj)=>{
            if(typeof v==='string') {
                obj[key] = (req, res) => {
                    let ret = v.replace('${nonce}', res.locals.cspNonce)
                    // const userAgent = useragent.parse(req.headers['user-agent'])
                    // safari don't support 'report-sample'
                    // if(/Safari/i.test(userAgent.family)){
                    //     ret = ret.replace("'report-sample'", '')
                    // }
                    ret = remove.reduce((ret,c)=>replaceString(ret, c, ''), ret)
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
        .filter(uri => !/^https?:\/\//i.test(uri))
    const strReports = reportUri.join(' ')

    // disable reportUri if it's empty
    options.directives.reportUri = strReports || false

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
        if(apiIndex >= 0 && isCSPPost(req)) {
            json(req, req.headers).then(val=>{
                console.log('csp-report:', val)
                console.log('user-agent:', uaString)
                res.status(204).end()
            }).catch(err=>{
                console.log('csp-report err:', err)
                next(err)
            })
        } else if(
            uaString && uaObj != null
            && !/HttpClient/i.test(uaObj.family)
            && !signature
            && req.accepts(options.accepts)
            && (!res.get('Content-Type') || String(res.get('Content-Type')).indexOf(mime.getType(options.accepts))>-1)
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
