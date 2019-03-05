const pathToRegexp = require('path-to-regexp');

module.exports = function check(table, reqUrl, reqMethod='') {
    return table.map(v=>[].concat(v)).find(entry => {
        let [testUrl, testMethod=''] = entry
        if(typeof testMethod==='object' && testMethod) {
            testMethod = testMethod.method || ''
        }
        return reqMethod.match(new RegExp(testMethod, 'i'))
            && pathToRegexp(testUrl).exec(reqUrl)
    });
}
